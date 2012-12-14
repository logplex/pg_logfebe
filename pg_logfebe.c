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
#endif

PG_MODULE_MAGIC;

#define FORMATTED_TS_LEN 128

/* GUC-configured destination of the log pages */
static char *logUnixSocketPath = NULL;
static char *ident = NULL;

/* Old hook storage for loading/unloading of the extension */
static emit_log_hook_type prev_emit_log_hook = NULL;
static void openSocket(int *dst, char *path);
static void closeSocket(int *fd);
static void logfebe_emit_log_hook(ErrorData *edata);

/* Caches the formatted start time */
static char cachedBackendStartTime[FORMATTED_TS_LEN];

/*
 * File descriptor that log records are written to.  Is re-set if a write
 * fails.
 */
static int outSockFd = -1;

void _PG_init(void);
void _PG_fini(void);

/*
 * Procedure that wraps a bunch of boilerplate GUC options appropriate for all
 * the options used in this extension.
 */
static void
optionalGucGet(char **dest, const char *name,
			   const char *shortDesc)
{
	PG_TRY();
	{
		*dest = GetConfigOptionByName(name, NULL);
	}
	PG_CATCH();
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
			NULL,
			NULL);
		EmitWarningsOnPlaceholders(name);
	}
	PG_END_TRY();
}

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

	/* Install hook */
	prev_emit_log_hook = emit_log_hook;
	emit_log_hook = logfebe_emit_log_hook;
}


static void
openSocket(int *dst, char *path)
{
	const int			save_errno = errno;
	struct sockaddr_un	addr;
	bool				formed;
	int					fd		   = -1;

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

	/* Connect socket to server. Or die.*/
	{
		int res;

		Assert(formed);
		res = connect(fd, (void *) &addr, sizeof addr);
		if (res < 0)
			goto err;
	}

	/* Everything worked; connection established. */
	Assert(fd >= 0);
	*dst = fd;
	goto exit;

err:
	/* Close and invalidate 'fd' if it got made */
	if (fd < 0)
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

static void
closeSocket(int *fd)
{
	const int save_errno = errno;

	do
	{
		errno = 0;

		/*
		 * Ignore errors except EINTR: other than EINTR, there is no
		 * obvious handling one can do from a failed close() that matters
		 * in this case.
		 */
		close(*fd);

		if (errno == EINTR)
			continue;

		*fd = -1;
	} while (*fd >= 0);

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
reCacheBackendStartTime()
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
	/* static counter for log sequence number */
	static long seqNum = 0;

	/* has counter been reset in current process? */
	static int	savedPid = 0;

	initStringInfo(dst);

	/*
	 * This is one of the few places where we'd rather not inherit a static
	 * variable's value from the postmaster.  But since we will, reset it when
	 * MyProcPid changes.
	 */
	if (savedPid != MyProcPid)
	{
		seqNum = 0;
		savedPid = MyProcPid;

		/* Invalidate cache */
		cachedBackendStartTime[0] = '\0';
	}

	seqNum += 1;

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

	/* Transaction id */
	{
		uint32_t nXid = htobe32(GetTopTransactionIdIfAny());

		appendBinaryStringInfo(dst, (void *) &nXid, sizeof nXid);
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

	/* errcontext */
	appendStringInfoPtr(dst, edata->context);

	/* user query --- only reported if not disabled by the caller */
	if (isLogLevelOutput(edata->elevel, log_min_error_statement) &&
		debug_query_string != NULL && !edata->hide_stmt)
	{
		appendStringInfoPtr(dst, debug_query_string);
	}
	else
		appendStringInfoPtr(dst, NULL);

	/* Write cursor position, although it can be garbage sometimes. */
	{
		uint32_t nCursorPos = htobe32(edata->cursorpos);

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

static void
logfebe_emit_log_hook(ErrorData *edata)
{
	int save_errno = errno;
	int bytesWritten;
	StringInfoData buf;
	StringInfoData framed;

	/* 
	 * Initialize StringInfoDatas early, because pfree is called
	 * unconditionally at exit.
	 */
	initStringInfo(&buf);
	initStringInfo(&framed);

	if (outSockFd < 0)
	{
		openSocket(&outSockFd, logUnixSocketPath);

		/* Couldn't get a valid socket; give up */
		if (outSockFd < 0)
			goto exit;
	}

	/*
	 * Format the output, and figure out how long it is, and frame it
	 * for the protocol.
	 */
	fmtLogMsg(&buf, edata);
	appendStringInfoChar(&framed, 'L');

	{
		uint32_t frsize = htobe32(buf.len);

		appendBinaryStringInfo(&framed, (void *) &frsize, sizeof frsize);
	}

	appendBinaryStringInfo(&framed, buf.data, buf.len);

writeAgain:
	errno = 0;
	bytesWritten = send(outSockFd, framed.data, framed.len, 0);

	if (bytesWritten < framed.len)
	{
		/*
		 * Something went wrong.
		 *
		 * The ErrorData passed to the hook goes un-logged in this case (except
		 * when errno is EINTR).
		 *
		 * Because outSockFd is opened as a blocking socket, it is
		 * expected that whenever a full write could not be achieved
		 * that something is awry, and that the connection should
		 * abandoned.
		 */
		Assert(errno != 0);

		/* Harmless and brief; just try again */
		if (errno == EINTR)
			goto writeAgain;

		/*
		 * Close and invalidate the socket fd; a new attempt to get a valid fd
		 * must come the next time this hook is called.
		 */
		closeSocket(&outSockFd);
		goto exit;
	}
	else
	{
		Assert(bytesWritten == len);
	}

exit:
	pfree(buf.data);
	pfree(framed.data);
	errno = save_errno;

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
