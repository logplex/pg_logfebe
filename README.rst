pg_logfebe
----------

``pg_logfebe`` produces detailed Postgres logs framed in the general
style of PostgreSQL's FEBE, the basis of the PostgreSQL wire protocol.

``pg_logfebe`` is implemented with a C extension that is to be loaded
via PostgreSQL's ``shared_preload_libraries`` configuration and hooks
into the logging system to provide sending detailed, structured log
output from PostgreSQL to another process via connecting to a unix
socket specified in ``postgresql.conf``.

This is useful to allow for rapid analysis, filtering, and forwarding
of large volumes of logs in another process that may be upgraded or
changed without too much difficulty or impact.

Configuration
=============

In ``postgresql.conf``::

   shared_preload_libraries = 'pg_logfebe'

   logfebe.unix_socket = '/wherever/log.sock'

   # The identity string is forwarded during connection start-up so
   # the receiver of logs can know what Postgres the log records are
   # coming from.
   logfebe.identity = 'a name of your choice'


Reporting Bugs
==============

Please contact daniel@fdr.io, daniel@heroku.com, and/or
security@heroku.com if you find a security-sensitive bug, such as (but
not limited to) denial of service, information disclosure, or remote
code execution.

Otherwise, please file an issue on the `project page on Github`__.

__ https://github.com/fdr/pg_logfebe/issues


List of Structured Fields Provided
==================================

The existing PostgreSQL CSV output code was used to populate this
list, and the meanings of the fields are the same and `can be
referenced in the PostgreSQL manual`__.  A sample parser and
human-readable renderer is seen (in the language "Go" in
``pg_logfebe_prototext.go``).  It can be useful for debugging.

__ http://www.postgresql.org/docs/current/static/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-CSVLOG

* LogTime
* UserName
* DatabaseName
* Pid
* ClientAddr
* SessionId
* SeqNum
* PsDisplay
* SessionStart
* Vxid
* Txid
* ELevel
* SQLState
* ErrMessage
* ErrDetail
* ErrHint
* InternalQuery
* InternalQueryPos
* ErrContext
* UserQuery
* UserQueryPos
* FileErrPos
* ApplicationName

What is FEBE Framing
====================

FEBE (sometimes rendered FE/BE) is the "Front-end/Back-end" protocol
that is the basis of virtually all PostgreSQL wire protocol
communications.

Each frame in this scheme is called a "Message".

The format looks like this::

    Message Type.  One 8-bit clean mnemonic ASCII character by
    convention, but could be any byte in principle.
    |
    |
    |  Message Length, 4 bytes, including the frame length (but not
    |  the type).  Network byte order integer.
    |  |
    |  |
    |  |     Message payload, (length - 4) bytes long.
    |  |     |
    |  |     |
    |  |     |
    v  v     v
   [-][----][...........]
    0  1234  5+

A simple de-framer can be seen in ``pg_logfebe_prototext.go`` in the
procedure ``readMessage``.

Protocol
========

``pg_logfebe`` is half-duplex: no response from the software receiving
``pg_logfebe`` traffic is required.  At connection startup, two
special messages are sent, followed by an infinite series of log
records.

A concrete implementation can be seen in ``pg_logfebe_prototext.go``,
in ``handleConnection``.

The protocol is versioned in its startup sequence to allow for gradual
change.

A server receiving ``pg_logfebe`` will receive a stream of messages
that will occur in this order::

   (T)ype              Payload
   ---------------------------

   (V)ersion           "PG-9.2.4/logfebe-1"

   (I)dentification    "Any-string-set-via-logfebe.identity"

   (L)og Record        [many structured fields]
   (L)og Record
   ...[Log Records ad-infinitum]...

Message Format Reference
========================

Reference guide:

* Fields are listed in order.

* All numerical types are network byte order.

* "CStrings" are NUL-terminated strings.

* "\*CStrings" are nullable-CStrings.  These are formatted like
  CStrings that always start with one byte: ``N``\(ull) or
  ``P``\(resent).  This is to disambiguate empty strings from C-`NULL`
  pointers in the PostgreSQL backend.

=======
Version
=======

::

   (V)ersion
           Version CString

The version is of the format "PG-9.2.4/logfebe-1", where the former
part is the Postgres version emitting the logs (as different versions
of Postgres may have slightly different ``LogRecord`` fields available
at some future time), and the latter part after the ``/`` is the
``pg_logfebe`` protocol version, which is to be incremented if the
protocol mechanics unrelated to the Postgres version are changed.

==============
Identification
==============

::

   (I)dentification
           Ident CString

==========
Log Record
==========

::

   (L)og Record
           LogTime          CString
           UserName         *CString
           DatabaseName     *CString
           Pid              int32
           ClientAddr       *CString
           SessionId        CString
           SeqNum           int64
           PsDisplay        *CString
           SessionStart     CString
           Vxid             *CString
           Txid             uint64
           ELevel           int32
           SQLState         *CString
           ErrMessage       *CString
           ErrDetail        *CString
           ErrHint          *CString
           InternalQuery    *CString
           InternalQueryPos int32
           ErrContext       *CString
           UserQuery        *CString
           UserQueryPos     int32
           FileErrPos       *CString
           ApplicationName  *CString
