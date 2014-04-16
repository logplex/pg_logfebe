/*
 * pg_logfebe.c
 *
 * Implements a module to be loaded via shared_preload_libraries that,
 * should "logfebe.unix_socket" be set in postgresql.conf will cause
 * log traffic to be written to the unix socket in question on a
 * best-effort basis.
 *
 * Portions Copyright (c) 1996-2012, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 * Portions Copyright (c) 2012, Heroku
 *
 */
#include "postgres.h"

#include <stdint.h>
#include <sys/un.h>
#include <unistd.h>

#include "access/xact.h"
#include "funcapi.h"
#include "lib/stringinfo.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "pg_config.h"
#include "pgtime.h"
#include "storage/proc.h"
#include "tcop/tcopprot.h"
#include "utils/elog.h"
#include "utils/guc.h"
#include "utils/ps_status.h"

/*
 * 64-bit byte-swapping, as per
 * http://stackoverflow.com/questions/809902/64-bit-ntohl-in-c
 */
#if defined(__linux__)
#  include <endian.h>
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#  include <sys/endian.h>
#elif defined(__OpenBSD__)
#  include <sys/types.h>
#  define be16toh(x) betoh16(x)
#  define be32toh(x) betoh32(x)
#  define be64toh(x) betoh64(x)
#elif defined(__darwin__)
#  include <libkern/OSByteOrder.h>
#  define htobe32(x) __DARWIN_OSSwapInt32(x)
#  define htobe64(x) __DARWIN_OSSwapInt64(x)
#endif

PG_MODULE_MAGIC;

#define FORMATTED_TS_LEN 128

/*
 * Startup version string, e.g. "PG-9.2.4/logfebe-1", where the
 * "logfebe-1" indicates the pg_logfebe protocol version.
 */
#define PROTO_VERSION ("PG-" PG_VERSION "/logfebe-1")

/* GUC-configured destination of the log pages */
static char *logUnixSocketPath = "";
static char *ident = "";

/* Old hook storage for loading/unloading of the extension */
static emit_log_hook_type prev_emit_log_hook = NULL;

/* Used to detect if values inherited over fork need resetting. */
static int savedPid = 0;

/* Caches the formatted start time */
static char cachedBackendStartTime[FORMATTED_TS_LEN];

/* Counter for log sequence number. */
static long seqNum = 0;

/*
 * File descriptor that log records are written to.
 *
 * Is re-set if a write fails.
 */
static int outSockFd = -1;

/* Dynamic linking hooks for Postgres */
void _PG_init(void);
void _PG_fini(void);

/* Internal function definitions*/
static bool formAddr(struct sockaddr_un *dst, char *path);
static bool isLogLevelOutput(int elevel, int log_min_level);
static void appendStringInfoPtr(StringInfo dst, const char *s);
static void closeSocket(int *fd);
static void fmtLogMsg(StringInfo dst, ErrorData *edata);
static void formatLogTime(char *dst, size_t dstSz, struct timeval tv);
static void formatNow(char *dst, size_t dstSz);
static void gucOnAssignCloseInvalidate(const char *newval, void *extra);
static void logfebe_emit_log_hook(ErrorData *edata);
static void openSocket(int *dst, char *path);
static void optionalGucGet(char **dest, const char *name,
						   const char *shortDesc);
static void reCacheBackendStartTime(void);
static void sendOrInval(int *fd, char *payload, size_t payloadSz);


/*
 * Useful for HUP triggered reassignment: invalidate the socket, which will
 * cause path information to be evaluated when reconnection and identification
 * to be re-exchanged.
 */
static void
gucOnAssignCloseInvalidate(const char *newval, void *extra)
{
	closeSocket(&outSockFd);
}

/*
 * Procedure that wraps a bunch of boilerplate GUC options appropriate for all
 * the options used in this extension.
 */
static void
optionalGucGet(char **dest, const char *name,
			   const char *shortDesc)
{
	DefineCustomStringVariable(
		name,
		shortDesc,
		"",
		dest,
		"",
		PGC_SIGHUP,
		GUC_NOT_IN_SAMPLE,
		NULL,
		gucOnAssignCloseInvalidate,
		NULL);
}

/*
 * Form a sockaddr_un for communication, returning false if this could not be
 * completed.
 */
static bool
formAddr(struct sockaddr_un *dst, char *path)
{
	size_t len;

	dst->sun_family = AF_UNIX;
	len = strlcpy(dst->sun_path, path, sizeof dst->sun_path);

	if (len <= sizeof dst->sun_path)
	{
		/* The copy could fit, and was copied. */
		return true;
	}

	/* Truncation; dst does not contain the full passed path. */
	return false;
}

/*
 * _PG_init()			- library load-time initialization
 *
 * DO NOT make this static nor change its name!
 *
 * Init the module, all we have to do here is getting our GUC
 */
void
_PG_init(void)
{
	/* Set up GUCs */
	optionalGucGet(&logUnixSocketPath, "logfebe.unix_socket",
				   "Unix socket to send logs to in FEBE frames.");
	optionalGucGet(&ident, "logfebe.identity",
				   "The identity of the installation of PostgreSQL.");

	EmitWarningsOnPlaceholders("logfebe");

	/* Install hook */
	prev_emit_log_hook = emit_log_hook;
	emit_log_hook = logfebe_emit_log_hook;
}


/*
 * Given an invalid Fd in *dst, try to open a unix socket connection to the
 * given path.
 */
static void
openSocket(int *dst, char *path)
{
	const int			save_errno = errno;
	struct sockaddr_un	addr;
	bool				formed;
	int					fd		   = -1;
	StringInfoData startup;

	/*
	 * This procedure is only defined on the domain of invalidated file
	 * descriptors
	 */
	Assert(*dst < 0);

	/* Begin attempting connection, first by forming the address */
	formed = formAddr(&addr, path);
	if (!formed)
	{
		/* Didn't work, give up */
		goto err;
	}

	/* Get socket fd, or die */
	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0)
		goto err;

	/* Connect socket to server. Or die. */
	Assert(formed);
	do
	{
		int res;

		errno = 0;
		res = connect(fd, (void *) &addr, sizeof addr);
		if (res < 0 || (errno != EINTR && errno != 0))
			goto err;
	} while (errno == EINTR);

	/*
	 * Connection established.
	 *
	 * Try to send start-up information as a service to the caller.  Should
	 * this fail, sendOrInval will close and invalidate the socket, though.
	 */
	Assert(fd >= 0);
	initStringInfo(&startup);

	/* Prepare startup: protocol version ('V') frame */
	{
		const uint32_t nVlen = htobe32((sizeof PROTO_VERSION) +
									   sizeof(u_int32_t));

		appendStringInfoChar(&startup, 'V');
		appendBinaryStringInfo(&startup, (void *) &nVlen, sizeof nVlen);
		appendBinaryStringInfo(&startup, PROTO_VERSION, sizeof PROTO_VERSION);
	}

	/* Prepare startup: system identification ('I') frame */
	{
		char			*payload;
		int				 payloadLen;
		uint32_t		 nPayloadLen;

		if (ident == NULL)
			payload = "";
		else
			payload = ident;

		payloadLen = strlen(payload) + sizeof '\0';
		nPayloadLen = htobe32(payloadLen + sizeof nPayloadLen);

		appendStringInfoChar(&startup, 'I');
		appendBinaryStringInfo(&startup, (void *) &nPayloadLen,
							   sizeof nPayloadLen);
		appendBinaryStringInfo(&startup, (void *) payload, payloadLen);
	}

	/*
	 * Try to send the prepared startup packet, invaliding fd if things go
	 * awry.
	 */
	sendOrInval(&fd, startup.data, startup.len);
	pfree(startup.data);
	*dst = fd;
	goto exit;

err:
	/* Close and invalidate 'fd' if it got made */
	if (fd >= 0)
	{
		closeSocket(&fd);
		Assert(fd < 0);
	}

	Assert(*dst < 0);
	goto exit;

exit:
	/* Universal post-condition */
	errno = save_errno;
	return;
}

/*
 * Perform a best-effort to close and invalidate a file descriptor.
 *
 * This exists to to encapsulate EINTR handling and invalidation.
 */
static void
closeSocket(int *fd)
{
	const int save_errno = errno;

	/*
	 * Close *fd and ignore EINTR, on advice from libusual's
	 * "safe_close" function:
	 *
	 * POSIX says close() can return EINTR but fd state is "undefined"
	 * later.  Seems Linux and BSDs close the fd anyway and EINTR is
	 * simply informative.  Thus retry is dangerous.
	 */
	close(*fd);
	*fd = -1;

	errno = save_errno;
}

static void
formatLogTime(char *dst, size_t dstSz, struct timeval tv)
{
	char				 msbuf[8];
	struct pg_tm		*tm;
	pg_time_t			 stamp_time;

	stamp_time = (pg_time_t) tv.tv_sec;
	tm = pg_localtime(&stamp_time, log_timezone);

	Assert(dstSz >= FORMATTED_TS_LEN);
	pg_strftime(dst, dstSz,
				/* leave room for milliseconds... */
				"%Y-%m-%d %H:%M:%S     %Z", tm);

	/* 'paste' milliseconds into place... */
	sprintf(msbuf, ".%03d", (int) (tv.tv_usec / 1000));
	strncpy(dst + 19, msbuf, 4);
}

static void
reCacheBackendStartTime(void)
{
	pg_time_t	stampTime = (pg_time_t) MyStartTime;

	/*
	 * Note: we expect that guc.c will ensure that log_timezone is set up (at
	 * least with a minimal GMT value) before Log_line_prefix can become
	 * nonempty or CSV mode can be selected.
	 */
	pg_strftime(cachedBackendStartTime, FORMATTED_TS_LEN,
				"%Y-%m-%d %H:%M:%S %Z",
				pg_localtime(&stampTime, log_timezone));
}

static void
formatNow(char *dst, size_t dstSz)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	Assert(dstSz >= FORMATTED_TS_LEN);
	formatLogTime(dst, dstSz, tv);
}

/*
 * isLogLevelOutput -- is elevel logically >= log_min_level?
 *
 * We use this for tests that should consider LOG to sort out-of-order,
 * between ERROR and FATAL.  Generally this is the right thing for testing
 * whether a message should go to the postmaster log, whereas a simple >=
 * test is correct for testing whether the message should go to the client.
 */
static bool
isLogLevelOutput(int elevel, int log_min_level)
{
	if (elevel == LOG || elevel == COMMERROR)
	{
		if (log_min_level == LOG || log_min_level <= ERROR)
			return true;
	}
	else if (log_min_level == LOG)
	{
		/* elevel != LOG */
		if (elevel >= FATAL)
			return true;
	}
	/* Neither is LOG */
	else if (elevel >= log_min_level)
		return true;

	return false;
}

/*
 * Append a string in a special format that prepends information about
 * its NULL-ity, should it be NULL.
 */
static void
appendStringInfoPtr(StringInfo dst, const char *s)
{
	/* 'N' for NULL, 'P' for "Present" */
	if (s == NULL)
		appendStringInfoChar(dst, 'N');
	else
	{
		appendStringInfoChar(dst, 'P');
		appendStringInfoString(dst, s);
	}

	appendStringInfoChar(dst, '\0');
}

static void
fmtLogMsg(StringInfo dst, ErrorData *edata)
{
	{
		char formattedLogTime[FORMATTED_TS_LEN];

		/* timestamp with milliseconds */
		formatNow(formattedLogTime, sizeof formattedLogTime);

		/*
		 * Always present, non-nullable; don't need to write the N/P
		 * header.
		 */
		appendStringInfoString(dst, formattedLogTime);
		appendStringInfoChar(dst, '\0');
	}

	/* username */
	if (MyProcPort)
		appendStringInfoPtr(dst, MyProcPort->user_name);
	else
		appendStringInfoPtr(dst, NULL);

	/* database name */
	if (MyProcPort)
		appendStringInfoPtr(dst, MyProcPort->database_name);
	else
		appendStringInfoPtr(dst, NULL);

	/* Process id  */
	{
		uint32_t nPid = htobe32(savedPid);

		appendBinaryStringInfo(dst, (void *) &nPid, sizeof nPid);
	}

	/* Remote host and port */
	if (MyProcPort && MyProcPort->remote_host)
	{
		/* 'present' string header, since this string is nullable */
		appendStringInfoChar(dst, 'P');

		appendStringInfoString(dst, MyProcPort->remote_host);
		if (MyProcPort->remote_port && MyProcPort->remote_port[0] != '\0')
		{
			appendStringInfoChar(dst, ':');
			appendStringInfoString(dst, MyProcPort->remote_port);
		}

		appendStringInfoChar(dst, '\0');
	}
	else
		appendStringInfoPtr(dst, NULL);

	/* session id; non-nullable */
	appendStringInfo(dst, "%lx.%x", (long) MyStartTime, MyProcPid);
	appendStringInfoChar(dst, '\0');

	/* Line number */
	{
		uint64_t nSeqNum = htobe64(seqNum);
		appendBinaryStringInfo(dst, (void *) &nSeqNum, sizeof nSeqNum);
	}

	/* PS display */
	if (MyProcPort)
	{
		StringInfoData msgbuf;
		const char *psdisp;
		int			displen;

		initStringInfo(&msgbuf);

		psdisp = get_ps_display(&displen);
		appendBinaryStringInfo(&msgbuf, psdisp, displen);

		appendStringInfoChar(dst, 'P');
		appendStringInfoString(dst, msgbuf.data);
		appendStringInfoChar(dst, '\0');

		pfree(msgbuf.data);
	}
	else
		appendStringInfoPtr(dst, NULL);

	/* session start timestamp */
	if (cachedBackendStartTime[0] == '\0')
	{
		/* Rebuild the cache if it was blown */
		reCacheBackendStartTime();
	}

	/* backend start time; non-nullable string */
	appendStringInfoString(dst, cachedBackendStartTime);
	appendStringInfoChar(dst, '\0');

	/*
	 * Virtual transaction id
	 *
	 * keep VXID format in sync with lockfuncs.c
	 */
	if (MyProc != NULL && MyProc->backendId != InvalidBackendId)
	{
		appendStringInfoChar(dst, 'P');
		appendStringInfo(dst, "%d/%u", MyProc->backendId, MyProc->lxid);
		appendStringInfoChar(dst, '\0');
	}
	else
		appendStringInfoPtr(dst, NULL);

	/*
	 * Transaction id
	 *
	 * This seems to be a mistake both here and in elog.c; in particular, it's
	 * not clear how the epoch would get added here.  However, leave room in
	 * the protocol to fix this later by upcasting.
	 */
	{
		uint64_t nTxid = htobe64((uint64) GetTopTransactionIdIfAny());

		appendBinaryStringInfo(dst, (void *) &nTxid, sizeof nTxid);
	}

	/* Error severity */
	{
		uint32_t nelevel = htobe32(edata->elevel);

		appendBinaryStringInfo(dst, (void *) &nelevel, sizeof nelevel);
	}

	/* SQL state code */
	appendStringInfoPtr(dst, unpack_sql_state(edata->sqlerrcode));

	/* errmessage */
	appendStringInfoPtr(dst, edata->message);

	/* errdetail or errdetail_log */
	if (edata->detail_log)
		appendStringInfoPtr(dst, edata->detail_log);
	else
		appendStringInfoPtr(dst, edata->detail);

	/* errhint */
	appendStringInfoPtr(dst, edata->hint);

	/* internal query */
	appendStringInfoPtr(dst, edata->internalquery);

	/* if printed internal query, print internal pos too */
	if (edata->internalpos > 0 && edata->internalquery != NULL)
	{
		uint32_t ninternalpos = htobe32(edata->internalpos);

		appendBinaryStringInfo(dst, (void *) &ninternalpos,
							   sizeof ninternalpos);
	}
	else
	{
		uint32_t ninternalpos = htobe32(-1);

		appendBinaryStringInfo(dst, (void *) &ninternalpos,
							   sizeof ninternalpos);
	}

	/* errcontext */
	appendStringInfoPtr(dst, edata->context);

	/*
	 * user query --- only reported if not disabled by the caller.
	 *
	 * Also include query position.
	 */
	if (isLogLevelOutput(edata->elevel, log_min_error_statement) &&
		debug_query_string != NULL && !edata->hide_stmt)
	{
		uint32_t nCursorPos = htobe32(edata->cursorpos);

		appendStringInfoPtr(dst, debug_query_string);
		appendBinaryStringInfo(dst, (void *) &nCursorPos, sizeof nCursorPos);
	}
	else
	{
		uint32_t nCursorPos = htobe32(-1);

		appendStringInfoPtr(dst, NULL);
		appendBinaryStringInfo(dst, (void *) &nCursorPos, sizeof nCursorPos);
	}

	/* file error location */
	if (Log_error_verbosity >= PGERROR_VERBOSE)
	{
		StringInfoData msgbuf;

		initStringInfo(&msgbuf);

		if (edata->funcname && edata->filename)
			appendStringInfo(&msgbuf, "%s, %s:%d",
							 edata->funcname, edata->filename,
							 edata->lineno);
		else if (edata->filename)
			appendStringInfo(&msgbuf, "%s:%d",
							 edata->filename, edata->lineno);

		appendStringInfoChar(dst, 'P');
		appendStringInfoString(dst, msgbuf.data);
		appendStringInfoChar(dst, '\0');

		pfree(msgbuf.data);
	}
	else
		appendStringInfoPtr(dst, NULL);

	/* application name */
	appendStringInfoPtr(dst, application_name);
}

/*
 * Send the payload or invalidate *fd.
 *
 * No confirmation of success or failure is delivered.
 */
static void
sendOrInval(int *fd, char *payload, size_t payloadSz)
{
	const int saved_errno = errno;
	ssize_t bytesWritten;

writeAgain:
	errno = 0;

	/*
	 * Send, and carefully suppress SIGPIPE, which otherwise will
	 * cause sendOrInval's error handling to function in since a
	 * failure will come in as a signal rather than an error code.
	 *
	 * This is required to allow re-connection in event the server
	 * closes the connection.
	 */
	bytesWritten = send(*fd, payload, payloadSz, MSG_NOSIGNAL);

	/*
	 * NB: Carefully perform signed-integer conversion to ssize_t;
	 * otherwise the comparison delivers unintuitive results.
	 */
	if (bytesWritten < (ssize_t) payloadSz)
	{
		/*
		 * Something went wrong.
		 *
		 * The ErrorData passed to the hook goes un-logged in this case (except
		 * when errno is EINTR).
		 *
		 * Because *fd is presumed a blocking socket, it is expected that
		 * whenever a full write could not be achieved that something is awry,
		 * and that the connection should abandoned.
		 */
		Assert(errno != 0);

		/* Harmless and brief; just try again */
		if (errno == EINTR)
			goto writeAgain;

		/*
		 * Close and invalidate the socket fd; a new attempt to get a valid fd
		 * must come the next time this hook is called.
		 */
		closeSocket(fd);
	}

	errno = saved_errno;
}

static void
logfebe_emit_log_hook(ErrorData *edata)
{
	int save_errno;
	StringInfoData buf;

	/*
	 * This is one of the few places where we'd rather not inherit a static
	 * variable's value from the postmaster.  But since we will, reset it when
	 * MyProcPid changes.
	 */
	if (savedPid != MyProcPid)
	{
		savedPid = MyProcPid;

		/* Invalidate all inherited values */
		seqNum = 0;
		cachedBackendStartTime[0] = '\0';

		if (outSockFd >= 0)
		{
			closeSocket(&outSockFd);
		}
	}

	/*
	 * Increment log sequence number
	 *
	 * Done early on so this happens regardless if there are problems emitting
	 * the log.
	 */
	seqNum += 1;

	/*
	 * Early exit if the socket path is not set and isn't in the format of
	 * an absolute path.
	 *
	 * The empty identity ("ident") is a valid one, so it is not rejected in
	 * the same way an empty logUnixSocketPath is.
	 */
	if (logUnixSocketPath == NULL ||
		strlen(logUnixSocketPath) <= 0 || logUnixSocketPath[0] != '/')
	{
		/*
		 * Unsetting the GUCs via SIGHUP would leave a connection
		 * dangling, if it exists, close it.
		 */
		if (outSockFd >= 0)
		{
			closeSocket(&outSockFd);
		}

		goto quickExit;
	}

	save_errno = errno;

	/*
	 * Initialize StringInfoDatas early, because pfree is called
	 * unconditionally at exit.
	 */
	initStringInfo(&buf);

	if (outSockFd < 0)
	{
		openSocket(&outSockFd, logUnixSocketPath);

		/* Couldn't get a valid socket; give up */
		if (outSockFd < 0)
			goto exit;
	}

	/*
	 * Make room for message type byte and length header.  The length header
	 * must be overwritten to the correct value at the end.
	 */
	{
		const char logHdr[5] = {'L', '\0', '\0', '\0', '\0'};

		appendBinaryStringInfo(&buf, logHdr, sizeof logHdr);
	}

	/*
	 * Format the output, and figure out how long it is, and frame it
	 * for the protocol.
	 */
	{
		uint32_t *msgSize;

		fmtLogMsg(&buf, edata);

		/*
		 * Check that buf is prepared properly, with enough space and
		 * the placeholder length expected.
		 */
		Assert(buf.len > 5);
		Assert(buf.data[0] == 'L');

		msgSize = (uint32_t *)(buf.data + 1);
		Assert(*msgSize == 0);

		/*
		 * Fill in *msgSize: buf contains the msg header, which is not
		 * included in length; subract and byte-swap to paste the
		 * right length into place.
		 */
		*msgSize = htobe32(buf.len - 1);
	}

	/* Finally: try to send the constructed message */
	sendOrInval(&outSockFd, buf.data, buf.len);

exit:
	pfree(buf.data);
	errno = save_errno;

quickExit:
	/* Call a previous hook, should it exist */
	if (prev_emit_log_hook != NULL)
		prev_emit_log_hook(edata);
}

/*
 * Module unload callback
 */
void
_PG_fini(void)
{
	/* Uninstall hook */
	emit_log_hook = prev_emit_log_hook;
}
