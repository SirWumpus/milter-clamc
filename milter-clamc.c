/*
 * milter-clamc.c
 *
 * Copyright 2006, 2012 by Anthony Howe. All rights reserved.
 *
 * The following should be added to the sendmail.mc file:
 *
 *	INPUT_MAIL_FILTER(
 *		`milter-clamc',
 *		`S=unix:/var/lib/milter-clamc/socket, T=S:10s;R:10s'
 *	)dnl
 *
 * $OpenBSD$
 */

/***********************************************************************
 *** Leave this header alone. Its generate from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 *** You can change the stuff below if the configure script doesn't work.
 ***********************************************************************/

#ifndef RUN_AS_USER
#define RUN_AS_USER			"milter"
#endif

#ifndef RUN_AS_GROUP
#define RUN_AS_GROUP			"milter"
#endif

#ifndef MILTER_CF
#define MILTER_CF			"/etc/mail/" MILTER_NAME ".cf"
#endif

#ifndef PID_FILE
#define PID_FILE			"/var/run/milter/" MILTER_NAME ".pid"
#endif

#ifndef SOCKET_FILE
#define SOCKET_FILE			"/var/run/milter/" MILTER_NAME ".socket"
#endif

#ifndef WORK_DIR
#define WORK_DIR			"/var/tmp"
#endif

#ifndef CLAMD_PORT
#define CLAMD_PORT			3310
#endif

#ifndef SUBJECT_TAG
#define SUBJECT_TAG			"[INFECTED]"
#endif

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

/* Re-assert this macro just in case. May cause a compiler warning. */
#define _REENTRANT	1

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <netdb.h>

#include <com/snert/lib/version.h>
#include <com/snert/lib/mail/limits.h>
#include <com/snert/lib/mail/smf.h>
#include <com/snert/lib/mail/smdb.h>
#include <com/snert/lib/util/Text.h>
#include <com/snert/lib/util/getopt.h>
#include <com/snert/lib/io/socket2.h>
#include <com/snert/lib/sys/Time.h>

#if LIBSNERT_MAJOR < 1 || LIBSNERT_MINOR < 75
# error "LibSnert 1.75.8 or better is required"
#endif

#ifdef MILTER_BUILD_STRING
# define MILTER_STRING	MILTER_NAME "/" MILTER_VERSION "." MILTER_BUILD_STRING
#else
# define MILTER_STRING	MILTER_NAME "/" MILTER_VERSION
#endif

/***********************************************************************
 *** Constants
 ***********************************************************************/

#define	TAG_FORMAT		"%05d %s: "
#define	TAG_ARGS		data->work.cid, data->work.qid

#define X_SCANNED_BY		"X-Scanned-By"
#define X_MILTER_PASS		"X-" MILTER_NAME "-Pass"
#define X_MILTER_REPORT		"X-" MILTER_NAME "-Report"

/***********************************************************************
 *** Global Variables
 ***********************************************************************/

typedef struct {
	smfWork work;
	Socket2 *clamd;				/* per message */
	Socket2 *session;			/* per message */
	int clamd_io_error;			/* per message */
	int hasPass;				/* per message */
	int hasReport;				/* per message */
	int hasSubject;				/* per message */
	long chunksSent;			/* per message */
	char line[SMTP_TEXT_LINE_LENGTH+1];	/* general purpose */
	char reply[SMTP_TEXT_LINE_LENGTH+1];	/* per message */
	char subject[SMTP_TEXT_LINE_LENGTH+1];	/* per message */
	char client_name[SMTP_DOMAIN_LENGTH+1];	/* per connection */
	char client_addr[IPV6_TAG_LENGTH+IPV6_STRING_LENGTH];	/* per connection */
} *workspace;

#define USAGE_POLICY							\
  "Policy to apply if message is undesirable. Specify either\n"		\
"# none, tag, quarantine, reject, or discard\n"				\
"#"

#define USAGE_CLAMD_POLICY						\
  "Policy to apply if there is a milter/clamd I/O error. Specify\n"	\
"# none, quarantine, reject, or discard\n"				\
"#"

static Option optIntro		= { "",	NULL, "\n# " MILTER_NAME "/" MILTER_VERSION "." MILTER_BUILD_STRING "\n#\n# " MILTER_COPYRIGHT "\n#\n" };
static Option optClamdMaxSize	= { "clamd-max-size",	"0",		"Max. number of kilobytes to pass to clamd, 0 for unlimited." };
static Option optClamdSocket	= { "clamd-socket",	"127.0.0.1:3310",	"The unix domain socket or internet host[,port] of the clamd server." };
static Option optClamdTimeout	= { "clamd-timeout",	"120",		"The milter/clamd I/O timeout in seconds." };
static Option optClamdPolicy	= { "clamd-policy",	"none",		USAGE_CLAMD_POLICY };
static Option optPolicy		= { "policy",		"reject",	USAGE_POLICY };
static Option optSubjectTag	= { "subject-tag",	SUBJECT_TAG,	"Subject tag for messages that are infected." };

#ifdef DROPPED_ADD_HEADERS
static Option optAddHeaders	= { "add-headers",	"-",		"Add extra informational headers when message passes." };
#endif

static Option *optTable[] = {
	&optIntro,
#ifdef DROPPED_ADD_HEADERS
	&optAddHeaders,
#endif
	&optClamdMaxSize,
	&optClamdPolicy,
	&optClamdSocket,
	&optClamdTimeout,
	&optPolicy,
	&optSubjectTag,
	NULL
};

/***********************************************************************
 *** Handlers
 ***********************************************************************/

/*
 * Open and allocate per-connection resources.
 */
static sfsistat
filterOpen(SMFICTX *ctx, char *client_name, _SOCK_ADDR *raw_client_addr)
{
	int access;
	workspace data;

	if (raw_client_addr == NULL) {
		smfLog(SMF_LOG_TRACE, "filterOpen() got NULL socket address, accepting connection");
		goto error0;
	}

	if (raw_client_addr->sa_family != AF_INET
#ifdef HAVE_STRUCT_SOCKADDR_IN6
	&& raw_client_addr->sa_family != AF_INET6
#endif
	) {
		smfLog(SMF_LOG_TRACE, "filterOpen() unsupported socket address type, accepting connection");
		goto error0;
	}

	if ((data = calloc(1, sizeof *data)) == NULL)
		goto error0;

	data->work.ctx = ctx;
	data->work.qid = smfNoQueue;
	data->work.cid = smfOpenProlog(ctx, client_name, raw_client_addr, data->client_addr, sizeof (data->client_addr));

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterOpen(%lx, '%s', [%s])", TAG_ARGS, (long) ctx, client_name, data->client_addr);

	if (smfi_setpriv(ctx, (void *) data) == MI_FAILURE) {
		syslog(LOG_ERR, TAG_FORMAT "failed to save workspace", TAG_ARGS);
		goto error1;
	}

	access = smfAccessHost(&data->work, MILTER_NAME "-connect:", client_name, data->client_addr, SMDB_ACCESS_OK);

	switch (access) {
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "connection %s [%s] blocked", client_name, data->client_addr);
#endif
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
	}

	TextCopy(data->client_name, sizeof (data->client_name), client_name);

	return SMFIS_CONTINUE;
error1:
	free(data);
error0:
	return SMFIS_ACCEPT;
}

static sfsistat
filterMail(SMFICTX *ctx, char **args)
{
	int access;
	workspace data;
	char *auth_authen;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterMail");

	if ((data->work.qid = smfi_getsymval(ctx, "i")) == NULL)
		data->work.qid = smfNoQueue;

	socketClose(data->session);
	data->session = NULL;

	socketClose(data->clamd);
	data->clamd = NULL;

	data->hasPass = 0;
	data->hasReport = 0;
	data->hasSubject = 0;
	data->chunksSent = 0;
	data->clamd_io_error = 0;
	data->work.skipMessage = data->work.skipConnection;
	auth_authen = smfi_getsymval(ctx, smMacro_auth_authen);

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterMail(%lx, %lx) MAIL='%s' auth='%s'", TAG_ARGS, (long) ctx, (long) args, args[0], auth_authen == NULL ? "" : auth_authen);

	access = smfAccessMail(&data->work, MILTER_NAME "-from:", args[0], SMDB_ACCESS_UNKNOWN);

	switch (access) {
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "sender blocked");
#endif
	}

	access = smfAccessAuth(&data->work, MILTER_NAME "-auth:", auth_authen, args[0], NULL, NULL);

	switch (access) {
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "sender blocked");
#endif
	case SMDB_ACCESS_OK:
		return SMFIS_ACCEPT;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterRcpt(SMFICTX *ctx, char **args)
{
	int access;
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterRcpt");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterRcpt(%lx, %lx) RCPT='%s'", TAG_ARGS, (long) ctx, (long) args, args[0]);

	access = smfAccessRcpt(&data->work, MILTER_NAME "-to:", args[0]);

	switch (access) {
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "recipient blocked");
#endif
	case SMDB_ACCESS_OK:
		data->work.skipMessage = 1;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
clamdError(workspace data, const char *fmt, ...)
{
	va_list args;

	if (data->clamd_io_error != 0)
		return SMFIS_CONTINUE;

	data->clamd_io_error = *optClamdPolicy.string;

	va_start(args, fmt);
	vsyslog(LOG_ERR, fmt, args);
	va_end(args);

	switch (*optClamdPolicy.string) {
	case 'd':
		return SMFIS_DISCARD;
	case 'r':
		return smfReply(&data->work, 550, NULL, "anti-virus unavailable");
	default:
		va_start(args, fmt);
		(void) vsnprintf(data->reply, sizeof (data->reply), fmt, args);
		va_end(args);
	}

	return SMFIS_CONTINUE;
}

static sfsistat
clamdStatus(workspace data)
{
	if (data->clamd_io_error == 0)
		return -1;

	switch (data->clamd_io_error) {
	case 'd':
		return SMFIS_DISCARD;
	case 'r':
		return SMFIS_REJECT;
#ifdef HAVE_SMFI_QUARANTINE
	case 'q':
		if (smfi_quarantine(data->work.ctx, data->reply) == MI_SUCCESS)
			return SMFIS_CONTINUE;
		/*@fallthrough@*/
#endif
	default:
		(void) smfHeaderSet(data->work.ctx, X_MILTER_REPORT, data->reply, 1, data->hasReport);
	}

	return SMFIS_CONTINUE;
}

static sfsistat
clamdConnect(workspace data)
{
	sfsistat rc;
	unsigned sessionPort;
	static char buffer[64];
	SocketAddress *caddr, *saddr;

	if (data->work.skipMessage)
		return -1;

	if ((caddr = socketAddressCreate(optClamdSocket.string, CLAMD_PORT)) == NULL) {
		rc = clamdError(data, TAG_FORMAT "clamd server address error: %s (%d)", TAG_ARGS, strerror(errno), errno);
		goto error0;
	}

	if ((data->clamd = socketOpen(caddr, 1)) == NULL) {
		rc = clamdError(data, TAG_FORMAT "clamd server open error: %s (%d)", TAG_ARGS, strerror(errno), errno);
		goto error1;
	}

	if (socketClient(data->clamd, optClamdTimeout.value)) {
		rc = clamdError(data, TAG_FORMAT "clamd server connection error: %s (%d)", TAG_ARGS, strerror(errno), errno);
		goto error2;
	}

	socketSetTimeout(data->clamd, optClamdTimeout.value);

	smfLog(SMF_LOG_DIALOG, TAG_FORMAT "> STREAM", TAG_ARGS);

	if (socketWrite(data->clamd, (unsigned char *) "STREAM\n", sizeof ("STREAM\n")-1) != sizeof ("STREAM\n")-1) {
		rc = clamdError(data, TAG_FORMAT "clamd server write error: %s (%d)", TAG_ARGS, strerror(errno), errno);
		goto error2;
	}

	if (socketReadLine(data->clamd, buffer, sizeof (buffer)) < 0) {
		rc = clamdError(data, TAG_FORMAT "clamd server read error: %s (%d)", TAG_ARGS, strerror(errno), errno);
		goto error2;
	}

	smfLog(SMF_LOG_DIALOG, TAG_FORMAT "< %s", TAG_ARGS, buffer);

	if (sscanf(buffer, "PORT %u", &sessionPort) != 1) {
		rc = clamdError(data, TAG_FORMAT "clamd session port \"%s\" parse error", TAG_ARGS, buffer);
		goto error2;
	}

	if ((saddr = socketAddressCreate(*optClamdSocket.string == '/' ? "0.0.0.0" : optClamdSocket.string, sessionPort)) == NULL) {
		rc = clamdError(data, TAG_FORMAT "clamd server address error: %s (%d)", TAG_ARGS, strerror(errno), errno);
		goto error2;
	}

	if (*optClamdSocket.string != '/')
		(void) socketAddressSetPort(saddr, sessionPort);

	if ((data->session = socketOpen(saddr, 1)) == NULL) {
		rc = clamdError(data, TAG_FORMAT "clamd session open error: %s (%d)", TAG_ARGS, strerror(errno), errno);
		goto error3;
	}

	if (socketClient(data->session, optClamdTimeout.value)) {
		rc = clamdError(data, TAG_FORMAT "clamd session connection error: %s (%d)", TAG_ARGS, strerror(errno), errno);
		goto error4;
	}

	socketSetTimeout(data->session, optClamdTimeout.value);

	free(saddr);
	free(caddr);

	return -1;
error4:
	socketClose(data->session);
	data->session = NULL;
error3:
	free(saddr);
error2:
	socketClose(data->clamd);
	data->clamd = NULL;
error1:
	free(caddr);
error0:
	return rc;
}

static sfsistat
filterHeader(SMFICTX *ctx, char *name, char *value)
{
	int length;
	sfsistat rc;
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterHeader");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterHeader(%lx, '%s', '%.20s...')", TAG_ARGS, (long) ctx, name, value);

	if (TextInsensitiveCompare(name, "Subject") == 0) {
		TextCopy(data->subject, sizeof (data->subject), value);
		data->hasSubject = 1;
	} else if (TextInsensitiveCompare(name, X_MILTER_PASS) == 0) {
		data->hasPass = 1;
	} else if (TextInsensitiveCompare(name, X_MILTER_REPORT) == 0) {
		data->hasReport = 1;
	}

	if (data->clamd_io_error != 0)
		return SMFIS_CONTINUE;

	if (data->clamd == NULL && (rc = clamdConnect(data)) != -1)
		return rc;

	if (data->session != NULL) {
		length = snprintf(data->line, sizeof (data->line), "%s: ", name);
		if (socketWrite(data->session, (unsigned char *) data->line, length) != length)
			return clamdError(data, TAG_FORMAT "anti-virus session write error (header name): %s (%d)", TAG_ARGS, strerror(errno), errno);

		length = strlen(value);
		if (socketWrite(data->session, (unsigned char *) value, length) != length)
			return clamdError(data, TAG_FORMAT "anti-virus session write error (header value): %s (%d)", TAG_ARGS, strerror(errno), errno);

		if (socketWrite(data->session, (unsigned char *) "\r\n", 2) != 2)
			return clamdError(data, TAG_FORMAT "anti-virus session write error (header newline): %s (%d)", TAG_ARGS, strerror(errno), errno);
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterEndHeaders(SMFICTX *ctx)
{
	sfsistat rc;
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterEndHeaders");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterEndHeaders(%lx)", TAG_ARGS, (long) ctx);

	if (data->clamd_io_error != 0)
		return SMFIS_CONTINUE;

	if (data->clamd == NULL && (rc = clamdConnect(data)) != -1)
		return rc;

	if (data->session != NULL && socketWrite(data->session, (unsigned char *) "\r\n", 2) != 2)
		return clamdError(data, TAG_FORMAT "anti-virus session write error (end of headers)", TAG_ARGS);

	return SMFIS_CONTINUE;
}

static sfsistat
filterBody(SMFICTX *ctx, unsigned char *chunk, size_t size)
{
	sfsistat rc;
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterBody");

	if (0 < optClamdMaxSize.value && optClamdMaxSize.value <= data->chunksSent)
		return SMFIS_CONTINUE;

	if (size == 0)
		chunk = (unsigned char *) "";
	else if (size < 20)
		chunk[--size] = '\0';

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterBody(%lx, '%.20s...', %lu) maxChunks=%ld chunksSent=%lu", TAG_ARGS, (long) ctx, chunk, (unsigned long) size, optClamdMaxSize.value, data->chunksSent);

	if (data->clamd_io_error != 0)
		return SMFIS_CONTINUE;

	if (data->clamd == NULL && (rc = clamdConnect(data)) != -1)
		return rc;

	if (data->session != NULL && socketWrite(data->session, chunk, size) != size)
		return clamdError(data, TAG_FORMAT "anti-virus session write error (body)", TAG_ARGS);

 	data->chunksSent++;

	if (0 < optClamdMaxSize.value && optClamdMaxSize.value <= data->chunksSent) {
		/* Signal EOF to clamd so that it can begin processing now.
		 * This should improve performance so that the result is
		 * ready by the time filterEndMessage() needs it.
		 */
		smfLog(SMF_LOG_DIALOG, TAG_FORMAT "EOF -> clamd", TAG_ARGS);
		socketClose(data->session);
		data->session = NULL;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterEndMessage(SMFICTX *ctx)
{
	sfsistat rc;
	workspace data;
	char *result, *found;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterEndMessage");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterEndMessage(%lx)", TAG_ARGS, (long) ctx);

	if (data->work.skipMessage)
		return SMFIS_CONTINUE;

	socketClose(data->session);
	data->session = NULL;

	/* Did we have clamd I/O error earlier to tag or quarantine? */
	if ((rc = clamdStatus(data)) != -1)
		return rc;

	if (data->clamd == NULL)
		return SMFIS_CONTINUE;

	*data->line = '\0';
	if (socketReadLine(data->clamd, data->line, sizeof (data->line)) <= 0) {
		(void) clamdError(data, TAG_FORMAT "anti-virus session read error: %s (%d)\n", TAG_ARGS, strerror(errno), errno);
		return clamdStatus(data);
	}

	socketClose(data->clamd);
	data->clamd = NULL;

	smfLog(SMF_LOG_DIALOG, TAG_FORMAT "< %s", TAG_ARGS, data->line);

	result = found = NULL;
	if (strncmp(data->line, "stream: ", sizeof ("stream: ")-1) == 0) {
		result = data->line + sizeof ("stream: ")-1;
		found = strstr(result, " FOUND");
		if (found != NULL)
			*found = '\0';
	} else {
		syslog(LOG_ERR, TAG_FORMAT "unexpected result: %s", TAG_ARGS, data->line);
	}

	if (found != NULL) {
		(void) snprintf(data->reply, sizeof (data->reply), "message is INFECTED with %s", result);
		if (*optPolicy.string != 'r')
			smfLog(SMF_LOG_INFO, TAG_FORMAT "%s", TAG_ARGS, data->reply);

		switch (*optPolicy.string) {
		case 'd':
			return SMFIS_DISCARD;
		case 'r':
			return smfReply(&data->work, 550, NULL, "%s", data->reply);
#ifdef HAVE_SMFI_QUARANTINE
		case 'q':
			if (smfi_quarantine(ctx, data->reply) == MI_SUCCESS)
				return SMFIS_CONTINUE;
			/*@fallthrough@*/
#endif
		case 't':
			if (TextInsensitiveStartsWith(data->subject, optSubjectTag.string) < 0) {
				(void) snprintf(data->line, sizeof (data->line), "%s %s", optSubjectTag.string, data->subject);
				(void) smfHeaderSet(ctx, "Subject", data->line, 1, data->hasSubject);
			}
			break;
		}

		(void) smfHeaderSet(ctx, X_MILTER_REPORT, data->reply, 1, data->hasReport);
	}

#ifdef DROPPED_ADD_HEADERS
	if (optAddHeaders.value) {
		long length;
		const char *if_name, *if_addr;

		if ((if_name = smfi_getsymval(ctx, "{if_name}")) == NULL)
			if_name = smfUndefined;
		if ((if_addr = smfi_getsymval(ctx, "{if_addr}")) == NULL)
			if_addr = "0.0.0.0";

		/* Add trace to the message. There can be many of these, one
		 * for each filter/host that looks at the message.
		 */
		length = snprintf(data->line, sizeof (data->line), MILTER_STRING " (%s [%s]); ", if_name, if_addr);
		length += TimeStampAdd(data->line + length, sizeof (data->line) - length);
		(void) smfi_addheader(ctx, X_SCANNED_BY, data->line);

		(void) smfHeaderSet(ctx, X_MILTER_PASS, found == NULL ? "YES" : "NO", 1, data->hasPass);
	}
#endif

	return SMFIS_CONTINUE;
}

/*
 * Close and release per-connection resources.
 */
static sfsistat
filterClose(SMFICTX *ctx)
{
	workspace data;
	unsigned short cid = 0;

	if ((data = (workspace) smfi_getpriv(ctx)) != NULL) {
		cid = smfCloseEpilog(&data->work);
		socketClose(data->session);
		socketClose(data->clamd);
		free(data);
	}

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterClose(%lx)", cid, smfNoQueue, (long) ctx);

	return SMFIS_CONTINUE;
}


/***********************************************************************
 ***  Milter Definition Block
 ***********************************************************************/

static smfInfo milter = {
	MILTER_MAJOR,
	MILTER_MINOR,
	MILTER_BUILD,
	MILTER_NAME,
	MILTER_AUTHOR,
	MILTER_COPYRIGHT,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	SMF_STDIO_CLOSE,

	/* struct smfiDesc */
	{
		MILTER_NAME,		/* filter name */
		SMFI_VERSION,		/* version code -- do not change */
		0,			/* flags */
		filterOpen,		/* connection info filter */
		NULL,			/* SMTP HELO command filter */
		filterMail,		/* envelope sender filter */
		filterRcpt,		/* envelope recipient filter */
		filterHeader,		/* header filter */
		filterEndHeaders,	/* end of header */
		filterBody,		/* body block filter */
		filterEndMessage,	/* end of message */
		NULL,			/* message aborted */
		filterClose		/* connection cleanup */
#if SMFI_VERSION > 2
		, NULL			/* Unknown/unimplemented commands */
#endif
#if SMFI_VERSION > 3
		, NULL			/* SMTP DATA command */
#endif
	}
};

/***********************************************************************
 *** Startup
 ***********************************************************************/

void
atExitCleanUp()
{
	smdbClose(smdbAccess);
	smfAtExitCleanUp();
}

int
main(int argc, char **argv)
{
	int argi;

	/* Default is OFF. */
	smfOptSmtpAuthOk.initial = "-";

	/* Defaults */
	smfOptFile.initial = MILTER_CF;
	smfOptPidFile.initial = PID_FILE;
	smfOptRunUser.initial = RUN_AS_USER;
	smfOptRunGroup.initial = RUN_AS_GROUP;
	smfOptWorkDir.initial = WORK_DIR;
	smfOptMilterSocket.initial = "unix:" SOCKET_FILE;

	/* Parse command line options looking for a file= option. */
	optionInit(optTable, smfOptTable, NULL);
	argi = optionArrayL(argc, argv, optTable, smfOptTable, NULL);

	/* Parse the option file followed by the command line options again. */
	if (smfOptFile.string != NULL && *smfOptFile.string != '\0') {
		/* Do NOT reset this option. */
		smfOptFile.initial = smfOptFile.string;
		smfOptFile.string = NULL;

		optionInit(optTable, smfOptTable, NULL);
		(void) optionFile(smfOptFile.string, optTable, smfOptTable, NULL);
		(void) optionArrayL(argc, argv, optTable, smfOptTable, NULL);
	}

	/* Show them the funny farm. */
	if (smfOptHelp.string != NULL) {
		optionUsageL(optTable, smfOptTable, NULL);
		exit(2);
	}

	if (smfOptQuit.string != NULL) {
		/* Use SIGQUIT signal in order to avoid delays
		 * caused by libmilter's handling of SIGTERM.
		 * smfi_stop() takes too long since it waits
		 * for connections to terminate, which could
		 * be a several minutes or longer.
		 */
		exit(pidKill(smfOptPidFile.string, SIGQUIT) != 0);
	}

	if (smfOptRestart.string != NULL) {
		(void) pidKill(smfOptPidFile.string, SIGQUIT);
		sleep(2);
	}

	if (smfOptDaemon.value && smfStartBackgroundProcess())
		return 1;

	(void) smfi_settimeout((int) smfOptMilterTimeout.value);
	(void) smfSetLogDetail(smfOptVerbose.string);

	openlog(MILTER_NAME, LOG_PID, LOG_MAIL);

	optClamdTimeout.value *= 1000;
	if (optClamdTimeout.value < 0)
		optClamdTimeout.value = 0;

	/* Convert from max. kilo bytes to body chunk units. */
	if (0 < optClamdMaxSize.value)
		optClamdMaxSize.value = 1 + optClamdMaxSize.value * 1024 / MILTER_CHUNK_SIZE;

#ifdef DROPPED_ADD_HEADERS
	if (optAddHeaders.value)
		milter.handlers.xxfi_flags |= SMFIF_ADDHDRS;
#endif

	switch (*optPolicy.string) {
#ifdef HAVE_SMFI_QUARANTINE
	case 'q':
		milter.handlers.xxfi_flags |= SMFIF_QUARANTINE;
		/*@fallthrough@*/
#endif
	case 't':
		/* Going to change the Subject: header and add a report. */
		milter.handlers.xxfi_flags |= SMFIF_ADDHDRS|SMFIF_CHGHDRS;
		break;
	}

	if (atexit(atExitCleanUp)) {
		syslog(LOG_ERR, "atexit() failed\n");
		return 1;
	}

	if (*smfOptAccessDb.string != '\0') {
		if (smfLogDetail & SMF_LOG_DATABASE)
			smdbSetDebugMask(SMDB_DEBUG_ALL);

		if ((smdbAccess = smdbOpen(smfOptAccessDb.string, 1)) == NULL) {
			syslog(LOG_ERR, "failed to open \"%s\"", smfOptAccessDb.string);
			return 1;
		}
	}

	if (smfLogDetail & SMF_LOG_SOCKET_ALL)
		socketSetDebug(10);
	else if (smfLogDetail & SMF_LOG_SOCKET_FD)
		socketSetDebug(1);

	if (socketInit()) {
		syslog(LOG_ERR, "socketInit() error\n");
		return 1;
	}

	return smfMainStart(&milter);
}
