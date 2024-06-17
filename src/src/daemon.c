/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2020 - 2024 */
/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Functions concerned with running Exim as a daemon */


#include "exim.h"


/* Structure for holding data for each SMTP connection */

typedef struct smtp_slot {
  pid_t		pid;		/* pid of the spawned reception process */
  uschar *	host_address;	/* address of the client host */
} smtp_slot;

typedef struct runner_slot {
  pid_t		pid;		/* pid of spawned queue-runner process */
  const uschar *queue_name;	/* pointer to the name in the qrunner struct */
} runner_slot;

/* An empty slot for initializing (Standard C does not allow constructor
expressions in assignments except as initializers in declarations). */

static smtp_slot empty_smtp_slot = { .pid = 0, .host_address = NULL };

/*************************************************
*               Local static variables           *
*************************************************/

static SIGNAL_BOOL sigchld_seen;
static SIGNAL_BOOL sighup_seen;
static SIGNAL_BOOL sigterm_seen;

static int   accept_retry_count = 0;
static int   accept_retry_errno;
static BOOL  accept_retry_select_failed;

static int   queue_run_count = 0;	/* current runners */

static unsigned queue_runner_slot_count = 0;
static runner_slot * queue_runner_slots = NULL;
static smtp_slot * smtp_slots = NULL;

static BOOL  write_pid = TRUE;

#ifndef EXIM_HAVE_ABSTRACT_UNIX_SOCKETS
static uschar * notifier_socket_name;
#endif


/*************************************************
*             SIGHUP Handler                     *
*************************************************/

/* All this handler does is to set a flag and re-enable the signal.

Argument: the signal number
Returns:  nothing
*/

static void
sighup_handler(int sig)
{
sighup_seen = TRUE;
signal(SIGHUP, sighup_handler);
}



/*************************************************
*     SIGCHLD handler for main daemon process    *
*************************************************/

/* Don't re-enable the handler here, since we aren't doing the
waiting here. If the signal is re-enabled, there will just be an
infinite sequence of calls to this handler. The SIGCHLD signal is
used just as a means of waking up the daemon so that it notices
terminated subprocesses as soon as possible.

Argument: the signal number
Returns:  nothing
*/

static void
main_sigchld_handler(int sig)
{
os_non_restarting_signal(SIGCHLD, SIG_DFL);
sigchld_seen = TRUE;
}


/* SIGTERM handler.  Try to get the daemon pid file removed
before exiting. */

static void
main_sigterm_handler(int sig)
{
sigterm_seen = TRUE;
}




/*************************************************
*          Unexpected errors in SMTP calls       *
*************************************************/

/* This function just saves a bit of repetitious coding.

Arguments:
  log_msg        Text of message to be logged
  smtp_msg       Text of SMTP error message
  was_errno      The failing errno

Returns:         nothing
*/

static void
never_error(uschar *log_msg, uschar *smtp_msg, int was_errno)
{
uschar *emsg = was_errno <= 0
  ? US"" : string_sprintf(": %s", strerror(was_errno));
log_write(0, LOG_MAIN|LOG_PANIC, "%s%s", log_msg, emsg);
if (smtp_out) smtp_printf("421 %s\r\n", SP_NO_MORE, smtp_msg);
}




/*************************************************
*************************************************/

static void
unlink_notifier_socket(void)
{
#ifndef EXIM_HAVE_ABSTRACT_UNIX_SOCKETS
DEBUG(D_any) debug_printf("unlinking notifier socket %s\n", notifier_socket_name);
Uunlink(notifier_socket_name);
#endif
}


static void
close_daemon_sockets(int daemon_notifier_fd,
  struct pollfd * fd_polls, int listen_socket_count)
{
if (daemon_notifier_fd >= 0)
  {
  (void) close(daemon_notifier_fd);
  daemon_notifier_fd = -1;
  }

for (int i = 0; i < listen_socket_count; i++) (void) close(fd_polls[i].fd);
}


/*************************************************
*            Handle a connected SMTP call        *
*************************************************/

/* This function is called when an SMTP connection has been accepted.
If there are too many, give an error message and close down. Otherwise
spin off a sub-process to handle the call. The list of listening sockets
is required so that they can be closed in the sub-process. Take care not to
leak store in this process - reset the stacking pool at the end.

Arguments:
  fd_polls        sockets which are listening for incoming calls
  listen_socket_count   count of listening sockets
  accept_socket         socket of the current accepted call
  accepted              socket information about the current call

Returns:            nothing
*/

static void
handle_smtp_call(struct pollfd * fd_polls, int listen_socket_count,
  int accept_socket, struct sockaddr *accepted)
{
pid_t pid;
union sockaddr_46 interface_sockaddr;
EXIM_SOCKLEN_T ifsize = sizeof(interface_sockaddr);
int dup_accept_socket = -1;
int max_for_this_host = 0;
int save_log_selector = *log_selector;
gstring * whofrom;

rmark reset_point = store_mark();

/* Make the address available in ASCII representation, and also fish out
the remote port. */

sender_host_address = host_ntoa(-1, accepted, NULL, &sender_host_port);
DEBUG(D_any) debug_printf("Connection request from %s port %d\n",
  sender_host_address, sender_host_port);

/* Set up the output stream, check the socket has duplicated, and set up the
input stream. These operations fail only the exceptional circumstances. Note
that never_error() won't use smtp_out if it is NULL. */

if (!(smtp_out = fdopen(accept_socket, "wb")))
  {
  never_error(US"daemon: fdopen() for smtp_out failed", US"", errno);
  goto ERROR_RETURN;
  }

if ((dup_accept_socket = dup(accept_socket)) < 0)
  {
  never_error(US"daemon: couldn't dup socket descriptor",
    US"Connection setup failed", errno);
  goto ERROR_RETURN;
  }

if (!(smtp_in = fdopen(dup_accept_socket, "rb")))
  {
  never_error(US"daemon: fdopen() for smtp_in failed",
    US"Connection setup failed", errno);
  goto ERROR_RETURN;
  }

/* Get the data for the local interface address. Panic for most errors, but
"connection reset by peer" just means the connection went away. */

if (getsockname(accept_socket, (struct sockaddr *)(&interface_sockaddr),
     &ifsize) < 0)
  {
  log_write(0, LOG_MAIN | ((errno == ECONNRESET)? 0 : LOG_PANIC),
    "getsockname() failed: %s", strerror(errno));
  smtp_printf("421 Local problem: getsockname() failed; please try again later\r\n", SP_NO_MORE);
  goto ERROR_RETURN;
  }

interface_address = host_ntoa(-1, &interface_sockaddr, NULL, &interface_port);
DEBUG(D_interface) debug_printf("interface address=%s port=%d\n",
  interface_address, interface_port);

/* Build a string identifying the remote host and, if requested, the port and
the local interface data. This is for logging; at the end of this function the
memory is reclaimed. */

whofrom = string_append(NULL, 3, "[", sender_host_address, "]");

if (LOGGING(incoming_port))
  whofrom = string_fmt_append(whofrom, ":%d", sender_host_port);

if (LOGGING(incoming_interface))
  whofrom = string_fmt_append(whofrom, " I=[%s]:%d",
    interface_address, interface_port);

/* Check maximum number of connections. We do not check for reserved
connections or unacceptable hosts here. That is done in the subprocess because
it might take some time. */

if (smtp_accept_max > 0 && smtp_accept_count >= smtp_accept_max)
  {
  DEBUG(D_any) debug_printf("rejecting SMTP connection: count=%d max=%d\n",
    smtp_accept_count, smtp_accept_max);
  smtp_printf("421 Too many concurrent SMTP connections; "
    "please try again later.\r\n", SP_NO_MORE);
  log_write(L_connection_reject,
            LOG_MAIN, "Connection from %Y refused: too many connections",
    whofrom);
  goto ERROR_RETURN;
  }

/* If a load limit above which only reserved hosts are acceptable is defined,
get the load average here, and if there are in fact no reserved hosts, do
the test right away (saves a fork). If there are hosts, do the check in the
subprocess because it might take time. */

if (smtp_load_reserve >= 0)
  {
  load_average = OS_GETLOADAVG();
  if (!smtp_reserve_hosts && load_average > smtp_load_reserve)
    {
    DEBUG(D_any) debug_printf("rejecting SMTP connection: load average = %.2f\n",
      (double)load_average/1000.0);
    smtp_printf("421 Too much load; please try again later.\r\n", SP_NO_MORE);
    log_write(L_connection_reject,
              LOG_MAIN, "Connection from %Y refused: load average = %.2f",
      whofrom, (double)load_average/1000.0);
    goto ERROR_RETURN;
    }
  }

/* Check that one specific host (strictly, IP address) is not hogging
resources. This is done here to prevent a denial of service attack by someone
forcing you to fork lots of times before denying service. The value of
smtp_accept_max_per_host is a string which is expanded. This makes it possible
to provide host-specific limits according to $sender_host address, but because
this is in the daemon mainline, only fast expansions (such as inline address
checks) should be used. The documentation is full of warnings. */

GET_OPTION("smtp_accept_max_per_host");
if (smtp_accept_max_per_host)
  {
  uschar * expanded = expand_string(smtp_accept_max_per_host);
  if (!expanded)
    {
    if (!f.expand_string_forcedfail)
      log_write(0, LOG_MAIN|LOG_PANIC, "expansion of smtp_accept_max_per_host "
        "failed for %Y: %s", whofrom, expand_string_message);
    }
  /* For speed, interpret a decimal number inline here */
  else
    {
    uschar * s = expanded;
    while (isdigit(*s))
      max_for_this_host = max_for_this_host * 10 + *s++ - '0';
    if (*s)
      log_write(0, LOG_MAIN|LOG_PANIC, "expansion of smtp_accept_max_per_host "
        "for %Y contains non-digit: %s", whofrom, expanded);
    }
  }

/* If we have fewer total connections than max_for_this_host, we can skip the
tedious per host_address checks. Note that at this stage smtp_accept_count
contains the count of *other* connections, not including this one. */

if (max_for_this_host > 0 && smtp_accept_count >= max_for_this_host)
  {
  int host_accept_count = 0;
  int other_host_count = 0;    /* keep a count of non matches to optimise */

  for (int i = 0; i < smtp_accept_max; ++i)
    if (smtp_slots[i].host_address)
      {
      if (Ustrcmp(sender_host_address, smtp_slots[i].host_address) == 0)
       host_accept_count++;
      else
       other_host_count++;

      /* Testing all these strings is expensive - see if we can drop out
      early, either by hitting the target, or finding there are not enough
      connections left to make the target. */

      if (  host_accept_count >= max_for_this_host
         || smtp_accept_count - other_host_count < max_for_this_host)
       break;
      }

  if (host_accept_count >= max_for_this_host)
    {
    DEBUG(D_any) debug_printf("rejecting SMTP connection: too many from this "
      "IP address: count=%d max=%d\n",
      host_accept_count, max_for_this_host);
    smtp_printf("421 Too many concurrent SMTP connections "
      "from this IP address; please try again later.\r\n", SP_NO_MORE);
    log_write(L_connection_reject,
              LOG_MAIN, "Connection from %Y refused: too many connections "
      "from that IP address", whofrom);
    search_tidyup();
    goto ERROR_RETURN;
    }
  }

/* OK, the connection count checks have been passed.
Now we can fork the accepting process; do a lookup tidy, just in case any
expansion above did a lookup. */

search_tidyup();
pid = exim_fork(US"daemon-accept");

/* Handle the child process */

if (pid == 0)
  {
  int queue_only_reason = 0;
  int old_pool = store_pool;
  int save_debug_selector = debug_selector;
  BOOL local_queue_only;
  BOOL session_local_queue_only;
#ifdef SA_NOCLDWAIT
  struct sigaction act;
#endif

  smtp_accept_count++;    /* So that it includes this process */
  connection_id = getpid();

  /* Log the connection if requested.
  In order to minimize the cost (because this is going to happen for every
  connection), do a preliminary selector test here. This saves ploughing through
  the generalized logging code each time when the selector is false. If the
  selector is set, check whether the host is on the list for logging. If not,
  arrange to unset the selector in the subprocess.

  jgh 2023/08/08 :- moved this logging in from the parent process, just
  pre-fork.  There was a claim back from 2004 that smtp_accept_count could have
  become out-of-date by the time the child could log it, and I can't see how
  that could happen. */

  if (LOGGING(smtp_connection))
    {
    uschar * list = hosts_connection_nolog;
    memset(sender_host_cache, 0, sizeof(sender_host_cache));
    if (list && verify_check_host(&list) == OK)
      save_log_selector &= ~L_smtp_connection;
    else if (LOGGING(connection_id))
      log_write(L_smtp_connection, LOG_MAIN, "SMTP connection from %Y "
	"Ci=%lu (TCP/IP connection count = %d)", whofrom, connection_id, smtp_accept_count);
    else
      log_write(L_smtp_connection, LOG_MAIN, "SMTP connection from %Y "
	"(TCP/IP connection count = %d)", whofrom, smtp_accept_count);
    }

  /* If the listen backlog was over the monitoring level, log it. */

  if (smtp_listen_backlog > smtp_backlog_monitor)
    log_write(0, LOG_MAIN, "listen backlog %d I=[%s]:%d",
		smtp_listen_backlog, interface_address, interface_port);

  /* May have been modified for the subprocess */

  *log_selector = save_log_selector;

  /* Get the local interface address into permanent store */

  store_pool = POOL_PERM;
  interface_address = string_copy(interface_address);
  store_pool = old_pool;

  /* Check for a tls-on-connect port */

  if (host_is_tls_on_connect_port(interface_port)) tls_in.on_connect = TRUE;

  /* Expand smtp_active_hostname if required. We do not do this any earlier,
  because it may depend on the local interface address (indeed, that is most
  likely what it depends on.) */

  smtp_active_hostname = primary_hostname;
  GET_OPTION("smtp_active_hostname");
  if (raw_active_hostname)
    {
    uschar * nah = expand_string(raw_active_hostname);
    if (!nah)
      {
      if (!f.expand_string_forcedfail)
        {
        log_write(0, LOG_MAIN|LOG_PANIC, "failed to expand \"%s\" "
          "(smtp_active_hostname): %s", raw_active_hostname,
          expand_string_message);
        smtp_printf("421 Local configuration error; "
          "please try again later.\r\n", SP_NO_MORE);
        mac_smtp_fflush();
        search_tidyup();
        exim_underbar_exit(EXIT_FAILURE);
        }
      }
    else if (*nah) smtp_active_hostname = nah;
    }

  /* Initialize the queueing flags */

  queue_check_only();
  session_local_queue_only = queue_only;

  /* Close the listening sockets, and set the SIGCHLD handler to SIG_IGN.
  We also attempt to set things up so that children are automatically reaped,
  but just in case this isn't available, there's a paranoid waitpid() in the
  loop too (except for systems where we are sure it isn't needed). See the more
  extensive comment before the reception loop in exim.c for a fuller
  explanation of this logic. */

  close_daemon_sockets(daemon_notifier_fd, fd_polls, listen_socket_count);

  /* Set FD_CLOEXEC on the SMTP socket. We don't want any rogue child processes
  to be able to communicate with them, under any circumstances. */
  (void)fcntl(accept_socket, F_SETFD,
              fcntl(accept_socket, F_GETFD) | FD_CLOEXEC);
  (void)fcntl(dup_accept_socket, F_SETFD,
              fcntl(dup_accept_socket, F_GETFD) | FD_CLOEXEC);

#ifdef SA_NOCLDWAIT
  act.sa_handler = SIG_IGN;
  sigemptyset(&(act.sa_mask));
  act.sa_flags = SA_NOCLDWAIT;
  sigaction(SIGCHLD, &act, NULL);
#else
  signal(SIGCHLD, SIG_IGN);
#endif
  signal(SIGTERM, SIG_DFL);
  signal(SIGINT, SIG_DFL);

  /* Attempt to get an id from the sending machine via the RFC 1413
  protocol. We do this in the sub-process in order not to hold up the
  main process if there is any delay. Then set up the fullhost information
  in case there is no HELO/EHLO.

  If debugging is enabled only for the daemon, we must turn if off while
  finding the id, but turn it on again afterwards so that information about the
  incoming connection is output. */

  if (f.debug_daemon) debug_selector = 0;
  verify_get_ident(IDENT_PORT);
  host_build_sender_fullhost();
  debug_selector = save_debug_selector;

  DEBUG(D_any)
    debug_printf("Process %d is handling incoming connection from %s\n",
      (int)getpid(), sender_fullhost);

  /* Now disable debugging permanently if it's required only for the daemon
  process. */

  if (f.debug_daemon) debug_selector = 0;

  /* If there are too many child processes for immediate delivery,
  set the session_local_queue_only flag, which is initialized from the
  configured value and may therefore already be TRUE. Leave logging
  till later so it will have a message id attached. Note that there is no
  possibility of re-calculating this per-message, because the value of
  smtp_accept_count does not change in this subprocess. */

  if (smtp_accept_queue > 0 && smtp_accept_count > smtp_accept_queue)
    {
    session_local_queue_only = TRUE;
    queue_only_reason = 1;
    }

  /* Handle the start of the SMTP session, then loop, accepting incoming
  messages from the SMTP connection. The end will come at the QUIT command,
  when smtp_setup_msg() returns 0. A break in the connection causes the
  process to die (see accept.c).

  NOTE: We do *not* call smtp_log_no_mail() if smtp_start_session() fails,
  because a log line has already been written for all its failure exists
  (usually "connection refused: <reason>") and writing another one is
  unnecessary clutter. */

  if (!smtp_start_session())
    {
    mac_smtp_fflush();
    search_tidyup();
    exim_underbar_exit(EXIT_SUCCESS);
    }

  for (;;)
    {
    int rc;
    message_id[0] = 0;            /* Clear out any previous message_id */
    reset_point = store_mark();   /* Save current store high water point */

    DEBUG(D_any)
      debug_printf("Process %d is ready for new message\n", (int)getpid());

    /* Smtp_setup_msg() returns 0 on QUIT or if the call is from an
    unacceptable host or if an ACL "drop" command was triggered, -1 on
    connection lost, and +1 on validly reaching DATA. Receive_msg() almost
    always returns TRUE when smtp_input is true; just retry if no message was
    accepted (can happen for invalid message parameters). However, it can yield
    FALSE if the connection was forcibly dropped by the DATA ACL. */

    if ((rc = smtp_setup_msg()) > 0)
      {
      BOOL ok = receive_msg(FALSE);
      search_tidyup();                    /* Close cached databases */
      if (!ok)                            /* Connection was dropped */
        {
	cancel_cutthrough_connection(TRUE, US"receive dropped");
        mac_smtp_fflush();
        smtp_log_no_mail();               /* Log no mail if configured */
        exim_underbar_exit(EXIT_SUCCESS);
        }
      if (!message_id[0]) continue;	/* No message was accepted */
      }
    else				/* bad smtp_setup_msg() */
      {
      if (smtp_out)
	{
	int fd = fileno(smtp_in);
	uschar buf[128];

	mac_smtp_fflush();
	/* drain socket, for clean TCP FINs */
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == 0)
	  for(int i = 16; read(fd, buf, sizeof(buf)) > 0 && i > 0; ) i--;
	}
      cancel_cutthrough_connection(TRUE, US"message setup dropped");
      search_tidyup();
      smtp_log_no_mail();                 /* Log no mail if configured */

      /*XXX should we pause briefly, hoping that the client will be the
      active TCP closer hence get the TCP_WAIT endpoint? */
      DEBUG(D_receive) debug_printf("SMTP>>(close on process exit)\n");
      exim_underbar_exit(rc ? EXIT_FAILURE : EXIT_SUCCESS);
      }

    /* Show the recipients when debugging */

    DEBUG(D_receive)
      {
      if (sender_address)
        debug_printf("Sender: %s\n", sender_address);
      if (recipients_list)
        {
        debug_printf("Recipients:\n");
        for (int i = 0; i < recipients_count; i++)
          debug_printf("  %s\n", recipients_list[i].address);
        }
      }

    /* A message has been accepted. Clean up any previous delivery processes
    that have completed and are defunct, on systems where they don't go away
    by themselves (see comments when setting SIG_IGN above). On such systems
    (if any) these delivery processes hang around after termination until
    the next message is received. */

    #ifndef SIG_IGN_WORKS
    while (waitpid(-1, NULL, WNOHANG) > 0);
    #endif

    /* Reclaim up the store used in accepting this message */

      {
      int r = receive_messagecount;
      BOOL q = f.queue_only_policy;
      smtp_reset(reset_point);
      reset_point = NULL;
      f.queue_only_policy = q;
      receive_messagecount = r;
      }

    /* If queue_only is set or if there are too many incoming connections in
    existence, session_local_queue_only will be TRUE. If it is not, check
    whether we have received too many messages in this session for immediate
    delivery. */

    if (!session_local_queue_only &&
        smtp_accept_queue_per_connection > 0 &&
        receive_messagecount > smtp_accept_queue_per_connection)
      {
      session_local_queue_only = TRUE;
      queue_only_reason = 2;
      }

    /* Initialize local_queue_only from session_local_queue_only. If it is not
    true, and queue_only_load is set, check that the load average is below it.
    If local_queue_only is set by this means, we also set if for the session if
    queue_only_load_latch is true (the default). This means that, once set,
    local_queue_only remains set for any subsequent messages on the same SMTP
    connection. This is a deliberate choice; even though the load average may
    fall, it doesn't seem right to deliver later messages on the same call when
    not delivering earlier ones. However, the are special circumstances such as
    very long-lived connections from scanning appliances where this is not the
    best strategy. In such cases, queue_only_load_latch should be set false. */

    if (  !(local_queue_only = session_local_queue_only)
       && queue_only_load >= 0
       && (local_queue_only = (load_average = OS_GETLOADAVG()) > queue_only_load)
       )
      {
      queue_only_reason = 3;
      if (queue_only_load_latch) session_local_queue_only = TRUE;
      }

    /* Log the queueing here, when it will get a message id attached, but
    not if queue_only is set (case 0). */

    if (local_queue_only) switch(queue_only_reason)
      {
      case 1: log_write(L_delay_delivery,
                LOG_MAIN, "no immediate delivery: too many connections "
                "(%d, max %d)", smtp_accept_count, smtp_accept_queue);
	      break;

      case 2: log_write(L_delay_delivery,
                LOG_MAIN, "no immediate delivery: more than %d messages "
                "received in one connection", smtp_accept_queue_per_connection);
	      break;

      case 3: log_write(L_delay_delivery,
                LOG_MAIN, "no immediate delivery: load average %.2f",
                (double)load_average/1000.0);
	      break;
      }

    /* If a delivery attempt is required, spin off a new process to handle it.
    If we are not root, we have to re-exec exim unless deliveries are being
    done unprivileged. */

    else if (  (!f.queue_only_policy || f.queue_smtp)
            && !f.deliver_freeze)
      {
      pid_t dpid;

      /* We used to flush smtp_out before forking so that buffered data was not
      duplicated, but now we want to pipeline the responses for data and quit.
      Instead, hard-close the fd underlying smtp_out right after fork to discard
      the data buffer. */

      if ((dpid = exim_fork(US"daemon-accept-delivery")) == 0)
        {
        (void)fclose(smtp_in);
	(void)close(fileno(smtp_out));
        (void)fclose(smtp_out);
	smtp_in = smtp_out = NULL;

        /* Don't ever molest the parent's SSL connection, but do clean up
        the data structures if necessary. */

#ifndef DISABLE_TLS
        tls_close(NULL, TLS_NO_SHUTDOWN);
#endif

        /* Reset SIGHUP and SIGCHLD in the child in both cases. */

        signal(SIGHUP,  SIG_DFL);
        signal(SIGCHLD, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);

        if (geteuid() != root_uid && !deliver_drop_privilege)
          {
          signal(SIGALRM, SIG_DFL);
	  delivery_re_exec(CEE_EXEC_PANIC);
          /* Control does not return here. */
          }

        /* No need to re-exec; SIGALRM remains set to the default handler */

        (void) deliver_message(message_id, FALSE, FALSE);
        search_tidyup();
        exim_underbar_exit(EXIT_SUCCESS);
        }

      if (dpid > 0)
        {
	release_cutthrough_connection(US"passed for delivery");
        DEBUG(D_any) debug_printf("forked delivery process %d\n", (int)dpid);
        }
      else
	{
	cancel_cutthrough_connection(TRUE, US"delivery fork failed");
        log_write(0, LOG_MAIN|LOG_PANIC, "daemon: delivery process fork "
          "failed: %s", strerror(errno));
	}
      }
    }
  }


/* Carrying on in the parent daemon process... Can't do much if the fork
failed. Otherwise, keep count of the number of accepting processes and
remember the pid for ticking off when the child completes. */

if (pid < 0)
  never_error(US"daemon: accept process fork failed", US"Fork failed", errno);
else
  {
  for (int i = 0; i < smtp_accept_max; ++i)
    if (smtp_slots[i].pid <= 0)
      {
      smtp_slots[i].pid = pid;
      /* Connection closes come asyncronously, so we cannot stack this store */
      if (smtp_accept_max_per_host)
        smtp_slots[i].host_address = string_copy_malloc(sender_host_address);
      smtp_accept_count++;
      break;
      }
  DEBUG(D_any) debug_printf("%d SMTP accept process%s running\n",
    smtp_accept_count, smtp_accept_count == 1 ? "" : "es");
  }

/* Get here via goto in error cases */

ERROR_RETURN:

/* Close the streams associated with the socket which will also close the
socket fds in this process. We can't do anything if fclose() fails, but
logging brings it to someone's attention. However, "connection reset by peer"
isn't really a problem, so skip that one. On Solaris, a dropped connection can
manifest itself as a broken pipe, so drop that one too. If the streams don't
exist, something went wrong while setting things up. Make sure the socket
descriptors are closed, in order to drop the connection. */

if (smtp_out)
  {
  if (fclose(smtp_out) != 0 && errno != ECONNRESET && errno != EPIPE)
    log_write(0, LOG_MAIN|LOG_PANIC, "daemon: fclose(smtp_out) failed: %s",
      strerror(errno));
  smtp_out = NULL;
  }
else (void)close(accept_socket);

if (smtp_in)
  {
  if (fclose(smtp_in) != 0 && errno != ECONNRESET && errno != EPIPE)
    log_write(0, LOG_MAIN|LOG_PANIC, "daemon: fclose(smtp_in) failed: %s",
      strerror(errno));
  smtp_in = NULL;
  }
else (void)close(dup_accept_socket);

/* Release any store used in this process, including the store used for holding
the incoming host address and an expanded active_hostname. */

log_close_all();
interface_address = sender_host_name = sender_host_address = NULL;
store_reset(reset_point);
}




/*************************************************
*       Check wildcard listen special cases      *
*************************************************/

/* This function is used when binding and listening on lists of addresses and
ports. It tests for special cases of wildcard listening, when IPv4 and IPv6
sockets may interact in different ways in different operating systems. It is
passed an error number, the list of listening addresses, and the current
address. Two checks are available: for a previous wildcard IPv6 address, or for
a following wildcard IPv4 address, in both cases on the same port.

In practice, pairs of wildcard addresses should be adjacent in the address list
because they are sorted that way below.

Arguments:
  eno            the error number
  addresses      the list of addresses
  ipa            the current IP address
  back           if TRUE, check for previous wildcard IPv6 address
                 if FALSE, check for a following wildcard IPv4 address

Returns:         TRUE or FALSE
*/

static BOOL
check_special_case(int eno, ip_address_item *addresses, ip_address_item *ipa,
  BOOL back)
{
ip_address_item *ipa2;

/* For the "back" case, if the failure was "address in use" for a wildcard IPv4
address, seek a previous IPv6 wildcard address on the same port. As it is
previous, it must have been successfully bound and be listening. Flag it as a
"6 including 4" listener. */

if (back)
  {
  if (eno != EADDRINUSE || ipa->address[0] != 0) return FALSE;
  for (ipa2 = addresses; ipa2 != ipa; ipa2 = ipa2->next)
    {
    if (ipa2->address[1] == 0 && ipa2->port == ipa->port)
      {
      ipa2->v6_include_v4 = TRUE;
      return TRUE;
      }
    }
  }

/* For the "forward" case, if the current address is a wildcard IPv6 address,
we seek a following wildcard IPv4 address on the same port. */

else
  {
  if (ipa->address[0] != ':' || ipa->address[1] != 0) return FALSE;
  for (ipa2 = ipa->next; ipa2 != NULL; ipa2 = ipa2->next)
    if (ipa2->address[0] == 0 && ipa->port == ipa2->port) return TRUE;
  }

return FALSE;
}




/*************************************************
*         Handle terminating subprocesses        *
*************************************************/

/* Handle the termination of child processes. Theoretically, this need be done
only when sigchld_seen is TRUE, but rumour has it that some systems lose
SIGCHLD signals at busy times, so to be on the safe side, this function is
called each time round. It shouldn't be too expensive.

Arguments:  none
Returns:    nothing
*/

static void
handle_ending_processes(void)
{
int status;
pid_t pid;

while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
  {
  DEBUG(D_any)
    {
    debug_printf("child %d ended: status=0x%x\n", (int)pid, status);
#ifdef WCOREDUMP
    if (WIFEXITED(status))
      debug_printf("  normal exit, %d\n", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
      debug_printf("  signal exit, signal %d%s\n", WTERMSIG(status),
          WCOREDUMP(status) ? " (core dumped)" : "");
#endif
    }

  /* If it's a listening daemon for which we are keeping track of individual
  subprocesses, deal with an accepting process that has terminated. */

  if (smtp_slots)
    {
    int i;
    for (i = 0; i < smtp_accept_max; i++)
      if (smtp_slots[i].pid == pid)
        {
        if (smtp_slots[i].host_address)
          store_free(smtp_slots[i].host_address);
        smtp_slots[i] = empty_smtp_slot;
        if (--smtp_accept_count < 0) smtp_accept_count = 0;
        DEBUG(D_any) debug_printf("%d SMTP accept process%s now running\n",
          smtp_accept_count, smtp_accept_count == 1 ? "" : "es");
        break;
        }
    if (i < smtp_accept_max) continue;  /* Found an accepting process */
    }

  /* If it wasn't an accepting process, see if it was a queue-runner
  process that we are tracking. */

  if (queue_runner_slots)
    for (unsigned i = 0; i < queue_runner_slot_count; i++)
      {
      runner_slot * r = queue_runner_slots + i;
      if (r->pid == pid)
        {
        r->pid = 0;			/* free up the slot */

        if (--queue_run_count < 0) queue_run_count = 0;
        DEBUG(D_any) debug_printf("%d queue-runner process%s now running\n",
          queue_run_count, queue_run_count == 1 ? "" : "es");

	for (qrunner ** p = &qrunners, * q = qrunners; q; p = &q->next, q = *p)
	  if (q->name == r->queue_name)
	    {
	    if (q->interval)		/* a periodic queue run */
	      q->run_count--;
	    else			/* a one-time run */
	      *p = q->next;		/* drop this qrunner */
	    break;
	    }
        break;
        }
      }
  }
}


static void
set_pid_file_path(void)
{
if (override_pid_file_path)
  pid_file_path = override_pid_file_path;

if (!*pid_file_path)
  pid_file_path = string_sprintf("%s/exim-daemon.pid", spool_directory);

if (pid_file_path[0] != '/')
  log_write(0, LOG_PANIC_DIE, "pid file path %s must be absolute\n", pid_file_path);
}


enum pid_op { PID_WRITE, PID_CHECK, PID_DELETE };

/* Do various pid file operations as safe as possible. Ideally we'd just
drop the privileges for creation of the pid file and not care at all about removal of
the file. FIXME.
Returns: true on success, false + errno==EACCES otherwise
*/

static BOOL
operate_on_pid_file(const enum pid_op operation, const pid_t pid)
{
char pid_line[sizeof(int) * 3 + 2];
const int pid_len = snprintf(pid_line, sizeof(pid_line), "%d\n", (int)pid);
BOOL lines_match = FALSE;
uschar * path, * base, * dir;

const int dir_flags = O_RDONLY | O_NONBLOCK;
const int base_flags = O_NOFOLLOW | O_NONBLOCK;
const mode_t base_mode = 0644;
struct stat sb;
int cwd_fd = -1, dir_fd = -1, base_fd = -1;
BOOL success = FALSE;
errno = EACCES;

set_pid_file_path();
if (!f.running_in_test_harness && real_uid != root_uid && real_uid != exim_uid) goto cleanup;
if (pid_len < 2 || pid_len >= (int)sizeof(pid_line)) goto cleanup;

path = string_copy(pid_file_path);
if ((base = Ustrrchr(path, '/')) == NULL)	/* should not happen, but who knows */
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "pid file path \"%s\" does not contain a '/'", pid_file_path);

dir = base != path ? path : US"/";
*base++ = '\0';

if (!dir || !*dir || *dir != '/') goto cleanup;
if (!base || !*base || Ustrchr(base, '/') != NULL) goto cleanup;

cwd_fd = open(".", dir_flags);
if (cwd_fd < 0 || fstat(cwd_fd, &sb) != 0 || !S_ISDIR(sb.st_mode)) goto cleanup;
dir_fd = open(CS dir, dir_flags);
if (dir_fd < 0 || fstat(dir_fd, &sb) != 0 || !S_ISDIR(sb.st_mode)) goto cleanup;

/* emulate openat */
if (fchdir(dir_fd) != 0) goto cleanup;
base_fd = open(CS base, O_RDONLY | base_flags);
if (fchdir(cwd_fd) != 0)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "can't return to previous working dir: %s", strerror(errno));

if (base_fd >= 0)
  {
  char line[sizeof(pid_line)];
  ssize_t len = -1;

  if (fstat(base_fd, &sb) != 0 || !S_ISREG(sb.st_mode)) goto cleanup;
  if ((sb.st_mode & 07777) != base_mode || sb.st_nlink != 1) goto cleanup;
  if (sb.st_size < 2 || sb.st_size >= (off_t)sizeof(line)) goto cleanup;

  len = read(base_fd, line, sizeof(line));
  if (len != (ssize_t)sb.st_size) goto cleanup;
  line[len] = '\0';

  if (strspn(line, "0123456789") != (size_t)len-1) goto cleanup;
  if (line[len-1] != '\n') goto cleanup;
  lines_match = len == pid_len && strcmp(line, pid_line) == 0;
  }

if (operation == PID_WRITE)
  {
  if (!lines_match)
    {
    if (base_fd >= 0)
      {
      int error = -1;
      /* emulate unlinkat */
      if (fchdir(dir_fd) != 0) goto cleanup;
      error = unlink(CS base);
      if (fchdir(cwd_fd) != 0)
        log_write(0, LOG_MAIN|LOG_PANIC_DIE, "can't return to previous working dir: %s", strerror(errno));
      if (error) goto cleanup;
      (void)close(base_fd);
      base_fd = -1;
     }
    /* emulate openat */
    if (fchdir(dir_fd) != 0) goto cleanup;
    base_fd = open(CS base, O_WRONLY | O_CREAT | O_EXCL | base_flags, base_mode);
    if (fchdir(cwd_fd) != 0)
        log_write(0, LOG_MAIN|LOG_PANIC_DIE, "can't return to previous working dir: %s", strerror(errno));
    if (base_fd < 0) goto cleanup;
    if (fchmod(base_fd, base_mode) != 0) goto cleanup;
    if (write(base_fd, pid_line, pid_len) != pid_len) goto cleanup;
    DEBUG(D_any) debug_printf("pid written to %s\n", pid_file_path);
    }
  }
else
  {
  if (!lines_match) goto cleanup;
  if (operation == PID_DELETE)
    {
    int error = -1;
    /* emulate unlinkat */
    if (fchdir(dir_fd) != 0) goto cleanup;
    error = unlink(CS base);
    if (fchdir(cwd_fd) != 0)
        log_write(0, LOG_MAIN|LOG_PANIC_DIE, "can't return to previous working dir: %s", strerror(errno));
    if (error) goto cleanup;
    }
  }

success = TRUE;
errno = 0;

cleanup:
if (cwd_fd >= 0) (void)close(cwd_fd);
if (dir_fd >= 0) (void)close(dir_fd);
if (base_fd >= 0) (void)close(base_fd);
return success;
}


/* Remove the daemon's pidfile.  Note: runs with root privilege,
as a direct child of the daemon.  Does not return. */

void
delete_pid_file(void)
{
const BOOL success = operate_on_pid_file(PID_DELETE, getppid());

DEBUG(D_any)
  debug_printf("delete pid file %s %s: %s\n", pid_file_path,
    success ? "success" : "failure", strerror(errno));

exim_exit(EXIT_SUCCESS);
}


/* Called by the daemon; exec a child to get the pid file deleted
since we may require privs for the containing directory */

static void
daemon_die(void)
{
int pid;

DEBUG(D_any) debug_printf("SIGTERM/SIGINT seen\n");
#if !defined(DISABLE_TLS) && (defined(EXIM_HAVE_INOTIFY) || defined(EXIM_HAVE_KEVENT))
tls_watch_invalidate();
#endif

if (daemon_notifier_fd >= 0)
  {
  close(daemon_notifier_fd);
  daemon_notifier_fd = -1;
  unlink_notifier_socket();
  }

if (f.running_in_test_harness || write_pid)
  {
  if ((pid = exim_fork(US"daemon-del-pidfile")) == 0)
    {
    if (override_pid_file_path)
      (void)child_exec_exim(CEE_EXEC_PANIC, FALSE, NULL, FALSE, 3,
	"-oP", override_pid_file_path, "-oPX");
    else
      (void)child_exec_exim(CEE_EXEC_PANIC, FALSE, NULL, FALSE, 1, "-oPX");

    /* Control never returns here. */
    }
  if (pid > 0)
    child_close(pid, 1);
  }
exim_exit(EXIT_SUCCESS);
}


/*************************************************
*	Listener socket for local work prompts	 *
*************************************************/

ssize_t
daemon_client_sockname(struct sockaddr_un * sup, uschar ** sname)
{
#ifdef EXIM_HAVE_ABSTRACT_UNIX_SOCKETS
sup->sun_path[0] = 0;  /* Abstract local socket addr - Linux-specific? */
return offsetof(struct sockaddr_un, sun_path) + 1
  + snprintf(sup->sun_path+1, sizeof(sup->sun_path)-1, "exim_%d", getpid());
#else
*sname = string_sprintf("%s/p_%d", spool_directory, getpid());
return offsetof(struct sockaddr_un, sun_path)
  + snprintf(sup->sun_path, sizeof(sup->sun_path), "%s", CS *sname);
#endif
}

ssize_t
daemon_notifier_sockname(struct sockaddr_un * sup)
{
GET_OPTION("notifier_socket");
#ifdef EXIM_HAVE_ABSTRACT_UNIX_SOCKETS
sup->sun_path[0] = 0;  /* Abstract local socket addr - Linux-specific? */
return offsetof(struct sockaddr_un, sun_path) + 1
  + snprintf(sup->sun_path+1, sizeof(sup->sun_path)-1, "%s",
              CS expand_string(notifier_socket));
#else
notifier_socket_name = expand_string(notifier_socket);
return offsetof(struct sockaddr_un, sun_path)
  + snprintf(sup->sun_path, sizeof(sup->sun_path), "%s",
              CS notifier_socket_name);
#endif
}


static void
daemon_notifier_socket(void)
{
int fd;
const uschar * where;
struct sockaddr_un sa_un = {.sun_family = AF_UNIX};
ssize_t len;

if (!f.notifier_socket_en)
  {
  DEBUG(D_any) debug_printf("-oY used so not creating notifier socket\n");
  return;
  }
if (override_local_interfaces && !override_pid_file_path)
  {
  DEBUG(D_any)
    debug_printf("-oX used without -oP so not creating notifier socket\n");
  return;
  }
if (!notifier_socket || !*notifier_socket)
  {
  DEBUG(D_any) debug_printf("no name for notifier socket\n");
  return;
  }

DEBUG(D_any) debug_printf("creating notifier socket\n");

#ifdef SOCK_CLOEXEC
if ((fd = socket(PF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0)) < 0)
  { where = US"socket"; goto bad; }
#else
if ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0)
  { where = US"socket"; goto bad; }
(void)fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif

len = daemon_notifier_sockname(&sa_un);

#ifdef EXIM_HAVE_ABSTRACT_UNIX_SOCKETS
DEBUG(D_any) debug_printf(" @%s\n", sa_un.sun_path+1);
#else			/* filesystem-visible and persistent; will neeed removal */
DEBUG(D_any) debug_printf(" %s\n", sa_un.sun_path);
#endif

if (bind(fd, (const struct sockaddr *)&sa_un, (socklen_t)len) < 0)
  { where = US"bind"; goto bad; }

#ifdef SO_PASSCRED		/* Linux */
if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) < 0)
  { where = US"SO_PASSCRED"; goto bad2; }
#elif defined(LOCAL_CREDS)	/* FreeBSD-ish */
if (setsockopt(fd, 0, LOCAL_CREDS, &on, sizeof(on)) < 0)
  { where = US"LOCAL_CREDS"; goto bad2; }
#endif

/* debug_printf("%s: fd %d\n", __FUNCTION__, fd); */
daemon_notifier_fd = fd;
return;

bad2:
#ifndef EXIM_HAVE_ABSTRACT_UNIX_SOCKETS
  Uunlink(sa_un.sun_path);
#endif
bad:
  log_write(0, LOG_MAIN|LOG_PANIC, "%s %s: %s",
    __FUNCTION__, where, strerror(errno));
  close(fd);
  return;
}


/* Data for notifier-triggered queue runs */

static uschar queuerun_msgid[MESSAGE_ID_LENGTH+1];
static const uschar * queuerun_msg_qname;


/* The notifier socket has something to read. Pull the message from it, decode
and do the action.
*/

static void
daemon_notification(void)
{
uschar buf[256], cbuf[256];
struct sockaddr_un sa_un;
struct iovec iov = {.iov_base = buf, .iov_len = sizeof(buf)-1};
struct msghdr msg = { .msg_name = &sa_un,
		      .msg_namelen = sizeof(sa_un),
		      .msg_iov = &iov,
		      .msg_iovlen = 1,
		      .msg_control = cbuf,
		      .msg_controllen = sizeof(cbuf)
		    };
ssize_t sz;

buf[sizeof(buf)-1] = 0;
if ((sz = recvmsg(daemon_notifier_fd, &msg, 0)) <= 0) return;
if (sz >= sizeof(buf)) return;

#ifdef notdef
debug_printf("addrlen %d\n", msg.msg_namelen);
#endif
DEBUG(D_queue_run)
  if (msg.msg_namelen > 0)
    {
    BOOL abstract = !*sa_un.sun_path;
    char * name = sa_un.sun_path + (abstract ? 1 : 0);
    int namelen =  (int)msg.msg_namelen - abstract ? 1 : 0;
    if (*name)
      debug_printf("%s from addr '%s%.*s'\n", __FUNCTION__,
	abstract ? "@" : "",
	namelen, name);
    else
      debug_printf("%s (from unknown addr)\n", __FUNCTION__);
    }
  else
    debug_printf("%s (from unknown addr)\n", __FUNCTION__);

/* Refuse to handle the item unless the peer has good credentials */
#ifdef SCM_CREDENTIALS
# define EXIM_SCM_CR_TYPE SCM_CREDENTIALS
#elif defined(LOCAL_CREDS) && defined(SCM_CREDS)
# define EXIM_SCM_CR_TYPE SCM_CREDS
#else
	/* The OS has no way to get the creds of the caller (for a unix/datagram socket.
	Punt; don't try to check. */
#endif

#ifdef EXIM_SCM_CR_TYPE
for (struct cmsghdr * cp = CMSG_FIRSTHDR(&msg);
     cp;
     cp = CMSG_NXTHDR(&msg, cp))
  if (cp->cmsg_level == SOL_SOCKET && cp->cmsg_type == EXIM_SCM_CR_TYPE)
  {
# ifdef SCM_CREDENTIALS					/* Linux */
  struct ucred * cr = (struct ucred *) CMSG_DATA(cp);
  if (cr->uid && cr->uid != exim_uid)
    {
    DEBUG(D_queue_run) debug_printf("%s: sender creds pid %d uid %d gid %d\n",
      __FUNCTION__, (int)cr->pid, (int)cr->uid, (int)cr->gid);
    }
# elif defined(LOCAL_CREDS)				/* BSD-ish */
  struct sockcred * cr = (struct sockcred *) CMSG_DATA(cp);
  if (cr->sc_uid && cr->sc_uid != exim_uid)
    {
    DEBUG(D_queue_run) debug_printf("%s: sender creds pid ??? uid %d gid %d\n",
      __FUNCTION__, (int)cr->sc_uid, (int)cr->sc_gid);
    }
# endif
  break;
  }
#endif

buf[sz] = 0;
switch (buf[0])
  {
#ifndef DISABLE_QUEUE_RAMP
  case NOTIFY_MSG_QRUN:
    /* this should be a message_id */
    DEBUG(D_queue_run)
      debug_printf("%s: qrunner trigger: %s\n", __FUNCTION__, buf+1);

    memcpy(queuerun_msgid, buf+1, MESSAGE_ID_LENGTH+1);

    for (qrunner * q = qrunners; q; q = q->next)
      if (q->name
	  ? Ustrcmp(q->name, buf+1+MESSAGE_ID_LENGTH+1) == 0
	  : !buf[1+MESSAGE_ID_LENGTH+1]
	 )
	{ queuerun_msg_qname = q->name; break; }
    return;
#endif

  case NOTIFY_QUEUE_SIZE_REQ:
    {
    uschar buf[16];
    int len = snprintf(CS buf, sizeof(buf), "%u", queue_count_cached());

    DEBUG(D_queue_run)
      debug_printf("%s: queue size request: %s\n", __FUNCTION__, buf);

    if (sendto(daemon_notifier_fd, buf, len, 0,
		(const struct sockaddr *)&sa_un, msg.msg_namelen) < 0)
      log_write(0, LOG_MAIN|LOG_PANIC,
	"%s: sendto: %s\n", __FUNCTION__, strerror(errno));
    break;
    }

  case NOTIFY_REGEX:
    regex_at_daemon(buf);
    break;
  }
return;
}



static void
daemon_inetd_wtimeout(time_t last_connection_time)
{
time_t resignal_interval = inetd_wait_timeout;

if (last_connection_time == (time_t)0)
  {
  DEBUG(D_any)
    debug_printf("inetd wait timeout expired, but still not seen first message, ignoring\n");
  }
else
  {
  time_t now = time(NULL);
  if (now == (time_t)-1)
    {
    DEBUG(D_any) debug_printf("failed to get time: %s\n", strerror(errno));
    }
  else if ((now - last_connection_time) >= inetd_wait_timeout)
    {
    DEBUG(D_any)
      debug_printf("inetd wait timeout %d expired, ending daemon\n",
	  inetd_wait_timeout);
    log_write(0, LOG_MAIN, "exim %s daemon terminating, inetd wait timeout reached.\n",
	version_string);
    daemon_die();		/* Does not return */
    }
  else
    resignal_interval -= (now - last_connection_time);
  }

sigalrm_seen = FALSE;
ALARM(resignal_interval);
}


/* Re-sort the qrunners list, and return the shortest interval.
That could be negatime.
The next-tick times should have been updated by any runs initiated,
though will not be when the global limit on runners was reached.

Unlikely to have many queues, so insertion-sort.
*/

static int
next_qrunner_interval(void)
{
qrunner * sorted = NULL;
for (qrunner * q = qrunners, * next; q; q = next)
  {
  next = q->next;
  q->next = NULL;
  if (sorted)
    {
    qrunner ** p = &sorted;
    for (qrunner * qq; qq = *p; p = &qq->next)
      if (  q->next_tick < qq->next_tick
	 || q->next_tick == qq->next_tick && q->interval < qq->interval
	 )
	{
	*p = q;
	q->next = qq;
	goto INSERTED;
	}
    *p = q;
  INSERTED: ;
    }
  else
    sorted = q;
  }
qrunners = sorted;
return qrunners ? qrunners->next_tick - time(NULL) : 0;
}

/* See if we can do a queue run.  If policy limit permit, kick one off.
If both notification and timer events are present, handle the former
and leave the timer outstanding.

Return the number of seconds until the next due runner.
*/

static int
daemon_qrun(int local_queue_run_max, struct pollfd * fd_polls, int listen_socket_count)
{
DEBUG(D_any) debug_printf("%s received\n",
#ifndef DISABLE_QUEUE_RAMP
  *queuerun_msgid ? "qrun notification" :
#endif
  "SIGALRM");

/* Do a full queue run in a child process, if required, unless we already have
enough queue runners on the go. If we are not running as root, a re-exec is
required. In the calling process, restart the alamr timer for the next run.  */

if (is_multiple_qrun())				/* we are managing periodic runs */
  if (local_queue_run_max <= 0 || queue_run_count < local_queue_run_max)
    {
    qrunner * q = NULL;

#ifndef DISABLE_QUEUE_RAMP
    /* If this is a triggered run for a specific message, see if we can start
    another runner for this queue. */

    if (*queuerun_msgid)
      {
      for (qrunner * qq = qrunners; qq; qq = qq->next)
	if (qq->name == queuerun_msg_qname)
	  {
	  q = qq->run_count < qq->run_max ? qq : NULL;
	  break;
	  }
      }
    else
#endif
      /* Normal periodic run: in order of run priority, find the first queue
      for which we can start a runner */

      for (q = qrunners; q; q = q->next)
	if (q->run_count < q->run_max) break;

    if (q)					/* found a queue to run */
      {
      pid_t pid;

      /* Bump this queue's next-tick by it's interval */

      if (q->interval)
	{
	time_t now = time(NULL);
	do ; while ((q->next_tick += q->interval) <= now);
	}

      if ((pid = exim_fork(US"queue-runner")) == 0)
	{
	/* Disable debugging if it's required only for the daemon process. We
	leave the above message, because it ties up with the "child ended"
	debugging messages. */

	if (f.debug_daemon) debug_selector = 0;

	/* Close any open listening sockets in the child */

	close_daemon_sockets(daemon_notifier_fd,
	  fd_polls, listen_socket_count);

	/* Reset SIGHUP and SIGCHLD in the child in both cases. */

	signal(SIGHUP,  SIG_DFL);
	signal(SIGCHLD, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGINT, SIG_DFL);

	/* Re-exec if privilege has been given up, unless deliver_drop_
	privilege is set. Reset SIGALRM before exec(). */

	if (geteuid() != root_uid && !deliver_drop_privilege)
	  {
	  uschar opt[8];
	  uschar *p = opt;
	  uschar *extra[7];
	  int extracount = 1;

	  signal(SIGALRM, SIG_DFL);
	  queue_name = US"";

	  *p++ = '-';
	  *p++ = 'q';
	  if (  q->queue_2stage
#ifndef DISABLE_QUEUE_RAMP
	     && !*queuerun_msgid
#endif
	     ) *p++ = 'q';
	  if (q->queue_run_first_delivery) *p++ = 'i';
	  if (q->queue_run_force) *p++ = 'f';
	  if (q->deliver_force_thaw) *p++ = 'f';
	  if (q->queue_run_local) *p++ = 'l';
	  *p = 0;

	  extra[0] = q->name
	    ? string_sprintf("%sG%s", opt, q->name) : opt;

#ifndef DISABLE_QUEUE_RAMP
	  if (*queuerun_msgid)
	    {
	    log_write(0, LOG_MAIN, "notify triggered queue run");
	    extra[extracount++] = queuerun_msgid;	/* Trigger only the */
	    extra[extracount++] = queuerun_msgid;	/* one message      */
	    }
#endif

	  /* If -R or -S were on the original command line, ensure they get
	  passed on. */

	  if (deliver_selectstring)
	    {
	    extra[extracount++] = f.deliver_selectstring_regex ? US"-Rr" : US"-R";
	    extra[extracount++] = deliver_selectstring;
	    }

	  if (deliver_selectstring_sender)
	    {
	    extra[extracount++] = f.deliver_selectstring_sender_regex
	      ? US"-Sr" : US"-S";
	    extra[extracount++] = deliver_selectstring_sender;
	    }

	  /* Overlay this process with a new execution. */

	  (void)child_exec_exim(CEE_EXEC_PANIC, FALSE, NULL, FALSE, extracount,
	    extra[0], extra[1], extra[2], extra[3], extra[4], extra[5], extra[6]);

	  /* Control never returns here. */
	  }

	/* No need to re-exec; SIGALRM remains set to the default handler */

#ifndef DISABLE_QUEUE_RAMP
	if (*queuerun_msgid)
	  {
	  log_write(0, LOG_MAIN, "notify triggered queue run");
	  f.queue_2stage = FALSE;
	  queue_run(q, queuerun_msgid, queuerun_msgid, FALSE);
	  }
	else
#endif
	  queue_run(q, NULL, NULL, FALSE);
	exim_underbar_exit(EXIT_SUCCESS);
	}

      if (pid < 0)
	{
	log_write(0, LOG_MAIN|LOG_PANIC, "daemon: fork of queue-runner "
	  "process failed: %s", strerror(errno));
	log_close_all();
	}
      else
	{
	for (int i = 0; i < local_queue_run_max; ++i)
	  if (queue_runner_slots[i].pid <= 0)
	    {
	    queue_runner_slots[i].pid = pid;
	    queue_runner_slots[i].queue_name = q->name;
	    q->run_count++;
	    queue_run_count++;
	    break;
	    }
	DEBUG(D_any) debug_printf("%d queue-runner process%s running\n",
	  queue_run_count, queue_run_count == 1 ? "" : "es");
	}
      }
    }

/* The queue run has been initiated (unless we were already running enough) */

#ifndef DISABLE_QUEUE_RAMP
if (*queuerun_msgid)		/* it was a fast-ramp kick; dealt with */
  *queuerun_msgid = 0;
else				/* periodic or one-time queue run */
#endif
  /* Set up next timer callback. Impose a minimum 1s tick,
  even when a run was outstanding */
  {
  int interval = next_qrunner_interval();
  if (interval <= 0) interval = 1;

  sigalrm_seen = FALSE;
  if (qrunners)			/* there are still periodic qrunners */
    {
    ALARM(interval);		/* set up next qrun tick */
    return interval;
    }
  }
return 0;
}




static const uschar *
describe_queue_runners(void)
{
gstring * g = NULL;

if (!is_multiple_qrun()) return US"no queue runs";

for (qrunner * q = qrunners; q; q = q->next)
  {
  g = string_catn(g, US"-q", 2);
  if (q->queue_2stage) g = string_catn(g, US"q", 1);
  if (q->name) g = string_append(g, 3, US"G", q->name, US"/");
  g = string_cat(g, readconf_printtime(q->interval));
  g = string_catn(g, US" ", 1);
  }
gstring_trim(g, 1);
gstring_release_unused(g);
return string_from_gstring(g);
}


/*************************************************
*              Exim Daemon Mainline              *
*************************************************/

/* The daemon can do two jobs, either of which is optional:

(1) Listens for incoming SMTP calls and spawns off a sub-process to handle
each one. This is requested by the -bd option, with -oX specifying the SMTP
port on which to listen (for testing).

(2) Spawns a queue-running process every so often. This is controlled by the
-q option with a an interval time. (If no time is given, a single queue run
is done from the main function, and control doesn't get here.)

Root privilege is required in order to attach to port 25. Some systems require
it when calling socket() rather than bind(). To cope with all cases, we run as
root for both socket() and bind(). Some systems also require root in order to
write to the pid file directory. This function must therefore be called as root
if it is to work properly in all circumstances. Once the socket is bound and
the pid file written, root privilege is given up if there is an exim uid.

There are no arguments to this function, and it never returns. */

void
daemon_go(void)
{
struct passwd * pw;
struct pollfd * fd_polls, * tls_watch_poll = NULL, * dnotify_poll = NULL;
int listen_socket_count = 0, poll_fd_count;
ip_address_item * addresses = NULL;
time_t last_connection_time = (time_t)0;
int local_queue_run_max = 0;

if (is_multiple_qrun())
  {
  /* Nuber of runner-tracking structs needed:  If the option queue_run_max has
  no expandable elements then it is the overall maximum; else we assume it
  depends on the queue name, and add them up to get the maximum.
  Evaluate both that and the individual limits. */

  GET_OPTION("queue_run_max");
  if (Ustrchr(queue_run_max, '$') != NULL)
    {
    for (qrunner * q = qrunners; q; q = q->next)
      {
      queue_name = q->name;
      local_queue_run_max +=
	(q->run_max = atoi(CS expand_string(queue_run_max)));
      }
    queue_name = US"";
    }
  else
    {
    local_queue_run_max = atoi(CS expand_string(queue_run_max));
    for (qrunner * q = qrunners; q; q = q->next)
      q->run_max = local_queue_run_max;
    }
  }

process_purpose = US"daemon";

/* If any debugging options are set, turn on the D_pid bit so that all
debugging lines get the pid added. */

DEBUG(D_any|D_v) debug_selector |= D_pid;

/* Allocate enough pollstructs for inetd mode plus the ancillary sockets;
also used when there are no listen sockets. */

fd_polls = store_get(sizeof(struct pollfd) * 3, GET_UNTAINTED);

if (f.inetd_wait_mode)
  {
  listen_socket_count = 1;
  (void) close(3);
  if (dup2(0, 3) == -1)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE,
        "failed to dup inetd socket safely away: %s", strerror(errno));

  fd_polls[0].fd = 3;
  fd_polls[0].events = POLLIN;
  (void) close(0);
  (void) close(1);
  (void) close(2);
  exim_nullstd();

  if (debug_file == stderr)
    {
    /* need a call to log_write before call to open debug_file, so that
    log.c:file_path has been initialised.  This is unfortunate. */
    log_write(0, LOG_MAIN, "debugging Exim in inetd wait mode starting");

    fclose(debug_file);
    debug_file = NULL;
    exim_nullstd(); /* re-open fd2 after we just closed it again */
    debug_logging_activate(US"-wait", NULL);
    }

  DEBUG(D_any) debug_printf("running in inetd wait mode\n");

  /* As per below, when creating sockets ourselves, we handle tcp_nodelay for
  our own buffering; we assume though that inetd set the socket REUSEADDR. */

  if (tcp_nodelay)
    if (setsockopt(3, IPPROTO_TCP, TCP_NODELAY, US &on, sizeof(on)))
      log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to set socket NODELAY: %s",
	strerror(errno));
  }


if (f.inetd_wait_mode || f.daemon_listen)
  {
  /* If any option requiring a load average to be available during the
  reception of a message is set, call os_getloadavg() while we are root
  for those OS for which this is necessary the first time it is called (in
  order to perform an "open" on the kernel memory file). */

#ifdef LOAD_AVG_NEEDS_ROOT
  if (queue_only_load >= 0 || smtp_load_reserve >= 0 ||
       (deliver_queue_load_max >= 0 && deliver_drop_privilege))
    (void)os_getloadavg();
#endif
  }


/* Do the preparation for setting up a listener on one or more interfaces, and
possible on various ports. This is controlled by the combination of
local_interfaces (which can set IP addresses and ports) and daemon_smtp_port
(which is a list of default ports to use for those items in local_interfaces
that do not specify a port). The -oX command line option can be used to
override one or both of these options.

If local_interfaces is not set, the default is to listen on all interfaces.
When it is set, it can include "all IPvx interfaces" as an item. This is useful
when different ports are in use.

It turns out that listening on all interfaces is messy in an IPv6 world,
because several different implementation approaches have been taken. This code
is now supposed to work with all of them. The point of difference is whether an
IPv6 socket that is listening on all interfaces will receive incoming IPv4
calls or not. We also have to cope with the case when IPv6 libraries exist, but
there is no IPv6 support in the kernel.

. On Solaris, an IPv6 socket will accept IPv4 calls, and give them as mapped
  addresses. However, if an IPv4 socket is also listening on all interfaces,
  calls are directed to the appropriate socket.

. On (some versions of) Linux, an IPv6 socket will accept IPv4 calls, and
  give them as mapped addresses, but an attempt also to listen on an IPv4
  socket on all interfaces causes an error.

. On OpenBSD, an IPv6 socket will not accept IPv4 calls. You have to set up
  two sockets if you want to accept both kinds of call.

. FreeBSD is like OpenBSD, but it has the IPV6_V6ONLY socket option, which
  can be turned off, to make it behave like the versions of Linux described
  above.

. I heard a report that the USAGI IPv6 stack for Linux has implemented
  IPV6_V6ONLY.

So, what we do when IPv6 is supported is as follows:

 (1) After it is set up, the list of interfaces is scanned for wildcard
     addresses. If an IPv6 and an IPv4 wildcard are both found for the same
     port, the list is re-arranged so that they are together, with the IPv6
     wildcard first.

 (2) If the creation of a wildcard IPv6 socket fails, we just log the error and
     carry on if an IPv4 wildcard socket for the same port follows later in the
     list. This allows Exim to carry on in the case when the kernel has no IPv6
     support.

 (3) Having created an IPv6 wildcard socket, we try to set IPV6_V6ONLY if that
     option is defined. However, if setting fails, carry on regardless (but log
     the incident).

 (4) If binding or listening on an IPv6 wildcard socket fails, it is a serious
     error.

 (5) If binding or listening on an IPv4 wildcard socket fails with the error
     EADDRINUSE, and a previous interface was an IPv6 wildcard for the same
     port (which must have succeeded or we wouldn't have got this far), we
     assume we are in the situation where just a single socket is permitted,
     and ignore the error.

Phew!

The preparation code decodes options and sets up the relevant data. We do this
first, so that we can return non-zero if there are any syntax errors, and also
write to stderr. */

if (f.daemon_listen && !f.inetd_wait_mode)
  {
  int *default_smtp_port;
  int sep;
  int pct = 0;
  uschar *s;
  const uschar * list;
  uschar *local_iface_source = US"local_interfaces";
  ip_address_item *ipa;
  ip_address_item **pipa;

  /* If -oX was used, disable the writing of a pid file unless -oP was
  explicitly used to force it. Then scan the string given to -oX. Any items
  that contain neither a dot nor a colon are used to override daemon_smtp_port.
  Any other items are used to override local_interfaces. */

  if (override_local_interfaces)
    {
    gstring * new_smtp_port = NULL;
    gstring * new_local_interfaces = NULL;

    if (!override_pid_file_path) write_pid = FALSE;

    list = override_local_interfaces;
    sep = 0;
    while ((s = string_nextinlist(&list, &sep, NULL, 0)))
      {
      uschar joinstr[4];
      gstring ** gp = Ustrpbrk(s, ".:") ? &new_local_interfaces : &new_smtp_port;

      if (!*gp)
        {
        joinstr[0] = sep;
        joinstr[1] = ' ';
        *gp = string_catn(*gp, US"<", 1);
        }

      *gp = string_catn(*gp, joinstr, 2);
      *gp = string_cat (*gp, s);
      }

    if (new_smtp_port)
      {
      daemon_smtp_port = string_from_gstring(new_smtp_port);
      DEBUG(D_any) debug_printf("daemon_smtp_port overridden by -oX:\n  %s\n",
        daemon_smtp_port);
      }

    if (new_local_interfaces)
      {
      local_interfaces = string_from_gstring(new_local_interfaces);
      local_iface_source = US"-oX data";
      DEBUG(D_any) debug_printf("local_interfaces overridden by -oX:\n  %s\n",
        local_interfaces);
      }
    }

  /* Create a list of default SMTP ports, to be used if local_interfaces
  contains entries without explicit ports. First count the number of ports, then
  build a translated list in a vector. */

  list = daemon_smtp_port;
  sep = 0;
  while ((s = string_nextinlist(&list, &sep, NULL, 0)))
    pct++;
  default_smtp_port = store_get((pct+1) * sizeof(int), GET_UNTAINTED);
  list = daemon_smtp_port;
  sep = 0;
  for (pct = 0;
       (s = string_nextinlist(&list, &sep, NULL, 0));
       pct++)
    {
    if (isdigit(*s))
      {
      uschar *end;
      default_smtp_port[pct] = Ustrtol(s, &end, 0);
      if (end != s + Ustrlen(s))
        log_write(0, LOG_PANIC_DIE|LOG_CONFIG, "invalid SMTP port: %s", s);
      }
    else
      {
      struct servent *smtp_service = getservbyname(CS s, "tcp");
      if (!smtp_service)
        log_write(0, LOG_PANIC_DIE|LOG_CONFIG, "TCP port \"%s\" not found", s);
      default_smtp_port[pct] = ntohs(smtp_service->s_port);
      }
    }
  default_smtp_port[pct] = 0;

  /* Check the list of TLS-on-connect ports and do name lookups if needed */

  list = tls_in.on_connect_ports;
  sep = 0;
  /* the list isn't expanded so cannot be tainted.  If it ever is we will trap here */
  while ((s = string_nextinlist(&list, &sep, big_buffer, big_buffer_size)))
    if (!isdigit(*s))
      {
      gstring * g = NULL;

      list = tls_in.on_connect_ports;
      tls_in.on_connect_ports = NULL;
      sep = 0;
      while ((s = string_nextinlist(&list, &sep, big_buffer, big_buffer_size)))
	{
        if (!isdigit(*s))
	  {
	  struct servent * smtp_service = getservbyname(CS s, "tcp");
	  if (!smtp_service)
	    log_write(0, LOG_PANIC_DIE|LOG_CONFIG, "TCP port \"%s\" not found", s);
	  s = string_sprintf("%d", (int)ntohs(smtp_service->s_port));
	  }
	g = string_append_listele(g, ':', s);
	}
      if (g)
	tls_in.on_connect_ports = g->s;
      break;
      }

  /* Create the list of local interfaces, possibly with ports included. This
  list may contain references to 0.0.0.0 and ::0 as wildcards. These special
  values are converted below. */

  addresses = host_build_ifacelist(local_interfaces, local_iface_source);

  /* In the list of IP addresses, convert 0.0.0.0 into an empty string, and ::0
  into the string ":". We use these to recognize wildcards in IPv4 and IPv6. In
  fact, many IP stacks recognize 0.0.0.0 and ::0 and handle them as wildcards
  anyway, but we need to know which are the wildcard addresses, and the shorter
  strings are neater.

  In the same scan, fill in missing port numbers from the default list. When
  there is more than one item in the list, extra items are created. */

  for (ipa = addresses; ipa; ipa = ipa->next)
    {
    if (Ustrcmp(ipa->address, "0.0.0.0") == 0)
      ipa->address[0] = 0;
    else if (Ustrcmp(ipa->address, "::0") == 0)
      {
      ipa->address[0] = ':';
      ipa->address[1] = 0;
      }

    if (ipa->port > 0) continue;

    if (daemon_smtp_port[0] <= 0)
      log_write(0, LOG_MAIN|LOG_PANIC_DIE, "no port specified for interface "
        "%s and daemon_smtp_port is unset; cannot start daemon",
        ipa->address[0] == 0 ? US"\"all IPv4\"" :
        ipa->address[1] == 0 ? US"\"all IPv6\"" : ipa->address);

    ipa->port = default_smtp_port[0];
    for (int i = 1; default_smtp_port[i] > 0; i++)
      {
      ip_address_item * new = store_get(sizeof(ip_address_item), GET_UNTAINTED);

      memcpy(new->address, ipa->address, Ustrlen(ipa->address) + 1);
      new->port = default_smtp_port[i];
      new->next = ipa->next;
      ipa->next = new;
      ipa = new;
      }
    }

  /* Scan the list of addresses for wildcards. If we find an IPv4 and an IPv6
  wildcard for the same port, ensure that (a) they are together and (b) the
  IPv6 address comes first. This makes handling the messy features easier, and
  also simplifies the construction of the "daemon started" log line. */

  pipa = &addresses;
  for (ipa = addresses; ipa; pipa = &ipa->next, ipa = ipa->next)
    {
    ip_address_item *ipa2;

    /* Handle an IPv4 wildcard */

    if (ipa->address[0] == 0)
      for (ipa2 = ipa; ipa2->next; ipa2 = ipa2->next)
        {
        ip_address_item *ipa3 = ipa2->next;
        if (ipa3->address[0] == ':' &&
            ipa3->address[1] == 0 &&
            ipa3->port == ipa->port)
          {
          ipa2->next = ipa3->next;
          ipa3->next = ipa;
          *pipa = ipa3;
          break;
          }
        }

    /* Handle an IPv6 wildcard. */

    else if (ipa->address[0] == ':' && ipa->address[1] == 0)
      for (ipa2 = ipa; ipa2->next; ipa2 = ipa2->next)
        {
        ip_address_item *ipa3 = ipa2->next;
        if (ipa3->address[0] == 0 && ipa3->port == ipa->port)
          {
          ipa2->next = ipa3->next;
          ipa3->next = ipa->next;
          ipa->next = ipa3;
          ipa = ipa3;
          break;
          }
        }
    }

  /* Get a vector to remember all the sockets in.
  Two extra elements for the ancillary sockets */

  for (ipa = addresses; ipa; ipa = ipa->next)
    listen_socket_count++;
  fd_polls = store_get(sizeof(struct pollfd) * (listen_socket_count + 2),
			    GET_UNTAINTED);
  for (struct pollfd * p = fd_polls; p < fd_polls + listen_socket_count + 2;
       p++)
    { p->fd = -1; p->events = POLLIN; }

  } /* daemon_listen but not inetd_wait_mode */

if (f.daemon_listen)
  {

  /* Do a sanity check on the max connects value just to save us from getting
  a huge amount of store. */

  if (smtp_accept_max > 4095) smtp_accept_max = 4096;

  /* There's no point setting smtp_accept_queue unless it is less than the max
  connects limit. The configuration reader ensures that the max is set if the
  queue-only option is set. */

  if (smtp_accept_queue > smtp_accept_max) smtp_accept_queue = 0;

  /* Get somewhere to keep the list of SMTP accepting pids if we are keeping
  track of them for total number and queue/host limits. */

  if (smtp_accept_max > 0)
    {
    smtp_slots = store_get(smtp_accept_max * sizeof(smtp_slot), GET_UNTAINTED);
    for (int i = 0; i < smtp_accept_max; i++) smtp_slots[i] = empty_smtp_slot;
    }
  }

/* The variable background_daemon is always false when debugging, but
can also be forced false in order to keep a non-debugging daemon in the
foreground. If background_daemon is true, close all open file descriptors that
we know about, but then re-open stdin, stdout, and stderr to /dev/null.  Also
do this for inetd_wait mode.

This is protection against any called functions (in libraries, or in
Perl, or whatever) that think they can write to stderr (or stdout). Before this
was added, it was quite likely that an SMTP connection would use one of these
file descriptors, in which case writing random stuff to it caused chaos.

Then disconnect from the controlling terminal, Most modern Unixes seem to have
setsid() for getting rid of the controlling terminal. For any OS that doesn't,
setsid() can be #defined as a no-op, or as something else. */

if (f.background_daemon || f.inetd_wait_mode)
  {
  log_close_all();    /* Just in case anything was logged earlier */
  search_tidyup();    /* Just in case any were used in reading the config. */
  (void)close(0);           /* Get rid of stdin/stdout/stderr */
  (void)close(1);
  (void)close(2);
  exim_nullstd();     /* Connect stdin/stdout/stderr to /dev/null */
  log_stderr = NULL;  /* So no attempt to copy paniclog output */
  }

if (f.background_daemon)
  {
  /* If the parent process of this one has pid == 1, we are re-initializing the
  daemon as the result of a SIGHUP. In this case, there is no need to do
  anything, because the controlling terminal has long gone. Otherwise, fork, in
  case current process is a process group leader (see 'man setsid' for an
  explanation) before calling setsid().
  All other forks want daemon_listen cleared. Rather than blow a register, jsut
  restore it here. */

  if (getppid() != 1)
    {
    BOOL daemon_listen = f.daemon_listen;
    pid_t pid = exim_fork(US"daemon");
    if (pid < 0) log_write(0, LOG_MAIN|LOG_PANIC_DIE,
      "fork() failed when starting daemon: %s", strerror(errno));
    if (pid > 0) exim_exit(EXIT_SUCCESS); /* in parent process, just exit */
    (void)setsid();                       /* release controlling terminal */
    f.daemon_listen = daemon_listen;
    }
  }

/* We are now in the disconnected, daemon process (unless debugging). Set up
the listening sockets if required. */

daemon_notifier_socket();

if (f.daemon_listen && !f.inetd_wait_mode)
  {
  int sk;
  ip_address_item *ipa;

  /* For each IP address, create a socket, bind it to the appropriate port, and
  start listening. See comments above about IPv6 sockets that may or may not
  accept IPv4 calls when listening on all interfaces. We also have to cope with
  the case of a system with IPv6 libraries, but no IPv6 support in the kernel.
  listening, provided a wildcard IPv4 socket for the same port follows. */

  for (ipa = addresses, sk = 0; sk < listen_socket_count; ipa = ipa->next, sk++)
    {
    BOOL wildcard;
    ip_address_item * ipa2;
    int fd, af;

    if (Ustrchr(ipa->address, ':') != NULL)
      {
      af = AF_INET6;
      wildcard = ipa->address[1] == 0;
      }
    else
      {
      af = AF_INET;
      wildcard = ipa->address[0] == 0;
      }

    if ((fd_polls[sk].fd = fd = ip_socket(SOCK_STREAM, af)) < 0)
      {
      if (check_special_case(0, addresses, ipa, FALSE))
        {
        log_write(0, LOG_MAIN, "Failed to create IPv6 socket for wildcard "
          "listening (%s): will use IPv4", strerror(errno));
        goto SKIP_SOCKET;
        }
      log_write(0, LOG_PANIC_DIE, "IPv%c socket creation failed: %s",
        af == AF_INET6 ? '6' : '4', strerror(errno));
      }

    /* If this is an IPv6 wildcard socket, set IPV6_V6ONLY if that option is
    available. Just log failure (can get protocol not available, just like
    socket creation can). */

#ifdef IPV6_V6ONLY
    if (af == AF_INET6 && wildcard &&
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0)
      log_write(0, LOG_MAIN, "Setting IPV6_V6ONLY on daemon's IPv6 wildcard "
        "socket failed (%s): carrying on without it", strerror(errno));
#endif  /* IPV6_V6ONLY */

    /* Set SO_REUSEADDR so that the daemon can be restarted while a connection
    is being handled.  Without this, a connection will prevent reuse of the
    smtp port for listening. */

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
      log_write(0, LOG_MAIN|LOG_PANIC_DIE, "setting SO_REUSEADDR on socket "
        "failed when starting daemon: %s", strerror(errno));

    /* Set TCP_NODELAY; Exim does its own buffering. There is a switch to
    disable this because it breaks some broken clients. */

    if (tcp_nodelay) setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

    /* Now bind the socket to the required port; if Exim is being restarted
    it may not always be possible to bind immediately, even with SO_REUSEADDR
    set, so try 10 times, waiting between each try. After 10 failures, we give
    up. In an IPv6 environment, if bind () fails with the error EADDRINUSE and
    we are doing wildcard IPv4 listening and there was a previous IPv6 wildcard
    address for the same port, ignore the error on the grounds that we must be
    in a system where the IPv6 socket accepts both kinds of call. This is
    necessary for (some release of) USAGI Linux; other IP stacks fail at the
    listen() stage instead. */

#ifdef TCP_FASTOPEN
    f.tcp_fastopen_ok = TRUE;
#endif
    for(;;)
      {
      uschar *msg, *addr;
      if (ip_bind(fd, af, ipa->address, ipa->port) >= 0) break;
      if (check_special_case(errno, addresses, ipa, TRUE))
        {
        DEBUG(D_any) debug_printf("wildcard IPv4 bind() failed after IPv6 "
          "listen() success; EADDRINUSE ignored\n");
        (void)close(fd);
        goto SKIP_SOCKET;
        }
      msg = US strerror(errno);
      addr = wildcard
        ? af == AF_INET6
	? US"(any IPv6)"
	: US"(any IPv4)"
	: ipa->address;
      if (daemon_startup_retries <= 0)
        log_write(0, LOG_MAIN|LOG_PANIC_DIE,
          "socket bind() to port %d for address %s failed: %s: "
          "daemon abandoned", ipa->port, addr, msg);
      log_write(0, LOG_MAIN, "socket bind() to port %d for address %s "
        "failed: %s: waiting %s before trying again (%d more %s)",
        ipa->port, addr, msg, readconf_printtime(daemon_startup_sleep),
        daemon_startup_retries, (daemon_startup_retries > 1)? "tries" : "try");
      daemon_startup_retries--;
      sleep(daemon_startup_sleep);
      }

    DEBUG(D_any)
      if (wildcard)
        debug_printf("listening on all interfaces (IPv%c) port %d\n",
          af == AF_INET6 ? '6' : '4', ipa->port);
      else
        debug_printf("listening on %s port %d\n", ipa->address, ipa->port);

    /* Start listening on the bound socket, establishing the maximum backlog of
    connections that is allowed. On success, add to the set of sockets for select
    and continue to the next address. */

#if defined(TCP_FASTOPEN) && !defined(__APPLE__)
    if (  f.tcp_fastopen_ok
       && setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN,
		    &smtp_connect_backlog, sizeof(smtp_connect_backlog)))
      {
      DEBUG(D_any) debug_printf("setsockopt FASTOPEN: %s\n", strerror(errno));
      f.tcp_fastopen_ok = FALSE;
      }
#endif
    if (listen(fd, smtp_connect_backlog) >= 0)
      {
#if defined(TCP_FASTOPEN) && defined(__APPLE__)
      if (  f.tcp_fastopen_ok
	 && setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &on, sizeof(on)))
	{
	DEBUG(D_any) debug_printf("setsockopt FASTOPEN: %s\n", strerror(errno));
	f.tcp_fastopen_ok = FALSE;
	}
#endif
      fd_polls[sk].fd = fd;
      continue;
      }

    /* Listening has failed. In an IPv6 environment, as for bind(), if listen()
    fails with the error EADDRINUSE and we are doing IPv4 wildcard listening
    and there was a previous successful IPv6 wildcard listen on the same port,
    we want to ignore the error on the grounds that we must be in a system
    where the IPv6 socket accepts both kinds of call. */

    if (!check_special_case(errno, addresses, ipa, TRUE))
      log_write(0, LOG_PANIC_DIE, "listen() failed on interface %s: %s",
        wildcard
	? af == AF_INET6 ? US"(any IPv6)" : US"(any IPv4)" : ipa->address,
        strerror(errno));

    DEBUG(D_any) debug_printf("wildcard IPv4 listen() failed after IPv6 "
      "listen() success; EADDRINUSE ignored\n");
    (void)close(fd);

    /* Come here if there has been a problem with the socket which we
    are going to ignore. We remove the address from the chain, and back up the
    counts. */

  SKIP_SOCKET:
    sk--;                          /* Back up the count */
    listen_socket_count--;         /* Reduce the total */
    if (ipa == addresses) addresses = ipa->next; else
      {
      for (ipa2 = addresses; ipa2->next != ipa; ipa2 = ipa2->next);
      ipa2->next = ipa->next;
      ipa = ipa2;
      }
    }          /* End of bind/listen loop for each address */
  }            /* End of setup for listening */


/* If we are not listening, we want to write a pid file only if -oP was
explicitly given. */

else if (!override_pid_file_path)
  write_pid = FALSE;

/* Write the pid to a known file for assistance in identification, if required.
We do this before giving up root privilege, because on some systems it is
necessary to be root in order to write into the pid file directory. There's
nothing to stop multiple daemons running, as long as no more than one listens
on a given TCP/IP port on the same interface(s). However, in these
circumstances it gets far too complicated to mess with pid file names
automatically. Consequently, Exim 4 writes a pid file only

  (a) When running in the test harness, or
  (b) When -bd is used and -oX is not used, or
  (c) When -oP is used to supply a path.

The variable daemon_write_pid is used to control this. */

if (f.running_in_test_harness || write_pid)
  {
  const enum pid_op operation = (f.running_in_test_harness
     || real_uid == root_uid
     || (real_uid == exim_uid && !override_pid_file_path)) ? PID_WRITE : PID_CHECK;
  if (!operate_on_pid_file(operation, getpid()))
    DEBUG(D_any) debug_printf("%s pid file %s: %s\n", (operation == PID_WRITE) ? "write" : "check", pid_file_path, strerror(errno));
  }

/* Set up the handler for SIGHUP, which causes a restart of the daemon. */

sighup_seen = FALSE;
signal(SIGHUP, sighup_handler);

/* Give up root privilege at this point (assuming that exim_uid and exim_gid
are not root). The third argument controls the running of initgroups().
Normally we do this, in order to set up the groups for the Exim user. However,
if we are not root at this time - some odd installations run that way - we
cannot do this. */

exim_setugid(exim_uid, exim_gid, geteuid()==root_uid, US"running as a daemon");

/* Update the originator_xxx fields so that received messages as listed as
coming from Exim, not whoever started the daemon. */

originator_uid = exim_uid;
originator_gid = exim_gid;
originator_login = (pw = getpwuid(exim_uid))
  ? string_copy_perm(US pw->pw_name, FALSE) : US"exim";

/* Get somewhere to keep the list of queue-runner pids if we are keeping track
of them (and also if we are doing queue runs). */

if (is_multiple_qrun() && local_queue_run_max > 0)
  {
  queue_runner_slot_count = local_queue_run_max;
  queue_runner_slots = store_get(local_queue_run_max * sizeof(runner_slot), GET_UNTAINTED);
  memset(queue_runner_slots, 0, local_queue_run_max * sizeof(runner_slot));
  }

/* Set up the handler for termination of child processes, and the one
telling us to die. */

sigchld_seen = FALSE;
os_non_restarting_signal(SIGCHLD, main_sigchld_handler);

sigterm_seen = FALSE;
os_non_restarting_signal(SIGTERM, main_sigterm_handler);
os_non_restarting_signal(SIGINT, main_sigterm_handler);

/* If we are to run the queue periodically, pretend the alarm has just gone
off. This will cause the first queue-runner to get kicked off straight away.
Get an initial sort of the list of queues, to prioritize the initial q-runs */


if ((sigalrm_seen = is_multiple_qrun()))
  (void) next_qrunner_interval();

/* Log the start up of a daemon - at least one of listening or queue running
must be set up. */

if (f.inetd_wait_mode)
  {
  uschar *p = big_buffer;

  if (inetd_wait_timeout >= 0)
    sprintf(CS p, "terminating after %d seconds", inetd_wait_timeout);
  else
    sprintf(CS p, "with no wait timeout");

  log_write(0, LOG_MAIN,
    "exim %s daemon started: pid=%d, launched with listening socket, %s",
    version_string, getpid(), big_buffer);
  set_process_info("daemon(%s): pre-listening socket", version_string);

  /* set up the timeout logic */
  sigalrm_seen = TRUE;
  }

else if (f.daemon_listen)
  {
  int smtp_ports = 0;
  int smtps_ports = 0;
  ip_address_item * ipa;
  uschar * p;
  const uschar * qinfo = describe_queue_runners();

  /* Build a list of listening addresses in big_buffer, but limit it to 10
  items. The style is for backwards compatibility.

  It is possible to have some ports listening for SMTPS (as opposed to TLS
  startted by STARTTLS), and others listening for standard SMTP. Keep their
  listings separate. */

  for (int j = 0, i; j < 2; j++)
    for (i = 0, ipa = addresses; i < 10 && ipa; i++, ipa = ipa->next)
      {
      /* First time round, look for SMTP ports; second time round, look for
      SMTPS ports. Build IP+port strings. */

      if (host_is_tls_on_connect_port(ipa->port) == (j > 0))
	{
	if (j == 0)
	  smtp_ports++;
	else
	  smtps_ports++;

	/* Now the information about the port (and sometimes interface) */

	if (ipa->address[0] == ':' && ipa->address[1] == 0)
	  {						/* v6 wildcard */
	  if (ipa->next && ipa->next->address[0] == 0 &&
	      ipa->next->port == ipa->port)
	    {
	    ipa->log = string_sprintf(" port %d (IPv6 and IPv4)", ipa->port);
	    (ipa = ipa->next)->log = NULL;
	    }
	  else if (ipa->v6_include_v4)
	    ipa->log = string_sprintf(" port %d (IPv6 with IPv4)", ipa->port);
	  else
	    ipa->log = string_sprintf(" port %d (IPv6)", ipa->port);
	  }
	else if (ipa->address[0] == 0)			/* v4 wildcard */
	  ipa->log = string_sprintf(" port %d (IPv4)", ipa->port);
	else				/* check for previously-seen IP */
	  {
	  ip_address_item * i2;
	  for (i2 = addresses; i2 != ipa; i2 = i2->next)
	    if (  host_is_tls_on_connect_port(i2->port) == (j > 0)
	       && Ustrcmp(ipa->address, i2->address) == 0
	       )
	      {				/* found; append port to list */
	      for (p = i2->log; *p; ) p++;	/* end of existing string   { */
	      if (*--p == '}') *p = '\0';	/* drop EOL */
	      while (isdigit(*--p)) ;		/* char before port */

	      i2->log = *p == ':'		/* no list yet?     { */
		? string_sprintf("%.*s{%s,%d}",
		  (int)(p - i2->log + 1), i2->log, p+1, ipa->port)
		: string_sprintf("%s,%d}", i2->log, ipa->port);
	      ipa->log = NULL;
	      break;
	      }
	  if (i2 == ipa)		/* first-time IP */
	    ipa->log = string_sprintf(" [%s]:%d", ipa->address, ipa->port);
	  }
	}
      }

  p = big_buffer;
  for (int j = 0, i; j < 2; j++)
    {
    /* First time round, look for SMTP ports; second time round, look for
    SMTPS ports. For the first one of each, insert leading text. */

    if (j == 0)
      {
      if (smtp_ports > 0)
	p += sprintf(CS p, "SMTP on");
      }
    else
      if (smtps_ports > 0)
	p += sprintf(CS p, "%sSMTPS on",
	  smtp_ports == 0 ? "" : " and for ");

    /* Now the information about the port (and sometimes interface) */

    for (i = 0, ipa = addresses; i < 10 && ipa; i++, ipa = ipa->next)
      if (host_is_tls_on_connect_port(ipa->port) == (j > 0))
	if (ipa->log)
	  p += sprintf(CS p, "%s",  ipa->log);

    if (ipa)
      p += sprintf(CS p, " ...");
    }

  log_write(0, LOG_MAIN,
    "exim %s daemon started: pid=%d, %s, listening for %s",
    version_string, getpid(), qinfo, big_buffer);
  set_process_info("daemon(%s): %s, listening for %s",
    version_string, qinfo, big_buffer);
  }

else	/* no listening sockets, only queue-runs */
  {
  const uschar * s = describe_queue_runners();
  log_write(0, LOG_MAIN,
    "exim %s daemon started: pid=%d, %s, not listening for SMTP",
    version_string, getpid(), s);
  set_process_info("daemon(%s): %s, not listening", version_string, s);
  }

/* Do any work it might be useful to amortize over our children
(eg: compile regex) */

dns_pattern_init();
smtp_deliver_init();	/* Used for callouts */

#ifndef DISABLE_DKIM
  {
# ifdef MEASURE_TIMING
  struct timeval t0;
  gettimeofday(&t0, NULL);
# endif
  dkim_exim_init();
# ifdef MEASURE_TIMING
  report_time_since(&t0, US"dkim_exim_init (delta)");
# endif
  }
#endif

#ifdef WITH_CONTENT_SCAN
malware_init();
#endif
#ifdef SUPPORT_SPF
spf_init();
#endif
#ifndef DISABLE_TLS
tls_daemon_init();
#endif

/* Add ancillary sockets to the set for select */

poll_fd_count = listen_socket_count;
#ifndef DISABLE_TLS
if (tls_watch_fd >= 0)
  {
  tls_watch_poll = &fd_polls[poll_fd_count++];
  tls_watch_poll->fd = tls_watch_fd;
  tls_watch_poll->events = POLLIN;
  }
#endif
if (daemon_notifier_fd >= 0)
  {
  dnotify_poll = &fd_polls[poll_fd_count++];
  dnotify_poll->fd = daemon_notifier_fd;
  dnotify_poll->events = POLLIN;
  }

/* Close the log so it can be renamed and moved. In the few cases below where
this long-running process writes to the log (always exceptional conditions), it
closes the log afterwards, for the same reason. */

log_close_all();

DEBUG(D_any) debug_print_ids(US"daemon running with");

/* Any messages accepted via this route are going to be SMTP. */

smtp_input = TRUE;

#ifdef MEASURE_TIMING
report_time_since(&timestamp_startup, US"daemon loop start");	/* testcase 0022 */
#endif

/* Enter the never-ending loop... */

for (;;)
  {
  int nolisten_sleep = 60;

  if (sigterm_seen)
    daemon_die();	/* Does not return */

  /* This code is placed first in the loop, so that it gets obeyed at the
  start, before the first wait, for the queue-runner case, so that the first
  one can be started immediately.

  The other option is that we have an inetd wait timeout specified to -bw. */

  if (sigalrm_seen || *queuerun_msgid)
    if (inetd_wait_timeout > 0)
      daemon_inetd_wtimeout(last_connection_time);	/* Might not return */
    else
      nolisten_sleep =
	daemon_qrun(local_queue_run_max, fd_polls, listen_socket_count);


  /* Sleep till a connection happens if listening, and handle the connection if
  that is why we woke up. The FreeBSD operating system requires the use of
  select() before accept() because the latter function is not interrupted by
  a signal, and we want to wake up for SIGCHLD and SIGALRM signals. Some other
  OS do notice signals in accept() but it does no harm to have the select()
  in for all of them - and it won't then be a lurking problem for ports to
  new OS. In fact, the later addition of listening on specific interfaces only
  requires this way of working anyway. */

  if (f.daemon_listen)
    {
    int lcount;
    BOOL select_failed = FALSE;

    DEBUG(D_any) debug_printf("Listening...\n");

    /* In rare cases we may have had a SIGCHLD signal in the time between
    setting the handler (below) and getting back here. If so, pretend that the
    select() was interrupted so that we reap the child. This might still leave
    a small window when a SIGCHLD could get lost. However, since we use SIGCHLD
    only to do the reaping more quickly, it shouldn't result in anything other
    than a delay until something else causes a wake-up.
    For the normal case, wait for either a pollable fd (eg. new connection) or
    or a SIGALRM (for a periodic queue run) */

    if (sigchld_seen)
      {
      lcount = -1;
      errno = EINTR;
      }
    else
      lcount = poll(fd_polls, poll_fd_count, -1);

    if (lcount < 0)
      {
      select_failed = TRUE;
      lcount = 1;
      }

    /* Clean up any subprocesses that may have terminated. We need to do this
    here so that smtp_accept_max_per_host works when a connection to that host
    has completed, and we are about to accept a new one. When this code was
    later in the sequence, a new connection could be rejected, even though an
    old one had just finished. Preserve the errno from any select() failure for
    the use of the common select/accept error processing below. */

      {
      int select_errno = errno;
      handle_ending_processes();

#ifndef DISABLE_TLS
      {
      int old_tfd;
      /* Create or rotate any required keys; handle (delayed) filewatch event */

      if ((old_tfd = tls_daemon_tick()) >= 0)
	for (struct pollfd * p = &fd_polls[listen_socket_count];
	     p < fd_polls + poll_fd_count; p++)
	  if (p->fd == old_tfd) { p->fd = tls_watch_fd ; break; }
      }
#endif
      errno = select_errno;
      }

    /* Loop for all the sockets that are currently ready to go. If select
    actually failed, we have set the count to 1 and select_failed=TRUE, so as
    to use the common error code for select/accept below. */

    while (lcount-- > 0)
      {
      int accept_socket = -1;
#if HAVE_IPV6
      struct sockaddr_in6 accepted;
#else
      struct sockaddr_in accepted;
#endif

      if (!select_failed)
	{
#if !defined(DISABLE_TLS) && (defined(EXIM_HAVE_INOTIFY) || defined(EXIM_HAVE_KEVENT))
	if (tls_watch_poll && tls_watch_poll->revents & POLLIN)
	  {
	  tls_watch_poll->revents = 0;
          tls_watch_trigger_time = time(NULL);	/* Set up delayed event */
	  tls_watch_discard_event(tls_watch_fd);
	  break;	/* to top of daemon loop */
	  }
#endif
	/* Handle the daemon-notifier socket.  If it was a fast-ramp
	notification then queuerun_msgid will have a nonzerolength string. */

	if (dnotify_poll && dnotify_poll->revents & POLLIN)
	  {
	  dnotify_poll->revents = 0;
	  daemon_notification();
	  break;	/* to top of daemon loop */
	  }
	for (struct pollfd * p = fd_polls; p < fd_polls + listen_socket_count;
	     p++)
	  if (p->revents & POLLIN)
            {
	    EXIM_SOCKLEN_T alen = sizeof(accepted);
#if defined(__FreeBSD__) && defined(SO_LISTENQLEN)
	    int backlog;
	    socklen_t blen = sizeof(backlog);

	    if (  smtp_backlog_monitor > 0
	       && getsockopt(p->fd, SOL_SOCKET, SO_LISTENQLEN, &backlog, &blen) == 0)
	      {
	      DEBUG(D_interface)
		debug_printf("listen fd %d queue curr %d\n", p->fd, backlog);
	      smtp_listen_backlog = backlog;
	      }

#elif defined(TCP_INFO) && defined(EXIM_HAVE_TCPI_UNACKED)
	    struct tcp_info ti;
	    socklen_t tlen = sizeof(ti);

	    /* If monitoring the backlog is wanted, grab for later logging */

	    smtp_listen_backlog = 0;
	    if (  smtp_backlog_monitor > 0
	       && getsockopt(p->fd, IPPROTO_TCP, TCP_INFO, &ti, &tlen) == 0)
	      {
	      DEBUG(D_interface) debug_printf("listen fd %d queue max %u curr %u\n",
		      p->fd, ti.tcpi_sacked, ti.tcpi_unacked);
	      smtp_listen_backlog = ti.tcpi_unacked;
	      }
#endif
	    p->revents = 0;
            accept_socket = accept(p->fd, (struct sockaddr *)&accepted, &alen);
            break;
            }
	}

      /* If select or accept has failed and this was not caused by an
      interruption, log the incident and try again. With asymmetric TCP/IP
      routing errors such as "No route to network" have been seen here. Also
      "connection reset by peer" has been seen. These cannot be classed as
      disastrous errors, but they could fill up a lot of log. The code in smail
      crashes the daemon after 10 successive failures of accept, on the grounds
      that some OS fail continuously. Exim originally followed suit, but this
      appears to have caused problems. Now it just keeps going, but instead of
      logging each error, it batches them up when they are continuous. */

      if (accept_socket < 0 && errno != EINTR)
        {
        if (accept_retry_count == 0)
          {
          accept_retry_errno = errno;
          accept_retry_select_failed = select_failed;
          }
        else if (  errno != accept_retry_errno
		|| select_failed != accept_retry_select_failed
		|| accept_retry_count >= 50)
	  {
	  log_write(0, LOG_MAIN | (accept_retry_count >= 50 ? LOG_PANIC : 0),
	    "%d %s() failure%s: %s",
	    accept_retry_count,
	    accept_retry_select_failed ? "select" : "accept",
	    accept_retry_count == 1 ? "" : "s",
	    strerror(accept_retry_errno));
	  log_close_all();
	  accept_retry_count = 0;
	  accept_retry_errno = errno;
	  accept_retry_select_failed = select_failed;
	  }
        accept_retry_count++;
        }
      else if (accept_retry_count > 0)
	{
	log_write(0, LOG_MAIN, "%d %s() failure%s: %s",
	  accept_retry_count,
	  accept_retry_select_failed ? "select" : "accept",
	  accept_retry_count == 1 ? "" : "s",
	  strerror(accept_retry_errno));
	log_close_all();
	accept_retry_count = 0;
	}

      /* If select/accept succeeded, deal with the connection. */

      if (accept_socket >= 0)
        {
#ifdef TCP_QUICKACK /* Avoid pure-ACKs while in tls protocol pingpong phase */
	/* Unfortunately we cannot be certain to do this before a TLS-on-connect
	Client Hello arrives and is acked. We do it as early as possible. */
	(void) setsockopt(accept_socket, IPPROTO_TCP, TCP_QUICKACK, US &off, sizeof(off));
#endif
        if (inetd_wait_timeout)
          last_connection_time = time(NULL);
        handle_smtp_call(fd_polls, listen_socket_count, accept_socket,
          (struct sockaddr *)&accepted);
        }
      }
    }

  /* If not listening, then just sleep for the queue interval. If we woke
  up early the last time for some other signal, it won't matter because
  the alarm signal will wake at the right time. This code originally used
  sleep() but it turns out that on the FreeBSD system, sleep() is not inter-
  rupted by signals, so it wasn't waking up for SIGALRM or SIGCHLD. Luckily
  select() can be used as an interruptible sleep() on all versions of Unix. */

  else
    {
    struct pollfd p;
    poll(&p, 0, nolisten_sleep * 1000);
    handle_ending_processes();
    }

  /* Re-enable the SIGCHLD handler if it has been run. It can't do it
  for itself, because it isn't doing the waiting itself. */

  if (sigchld_seen)
    {
    sigchld_seen = FALSE;
    os_non_restarting_signal(SIGCHLD, main_sigchld_handler);
    }

  /* Handle being woken by SIGHUP. We know at this point that the result
  of accept() has been dealt with, so we can re-exec exim safely, first
  closing the listening sockets so that they can be reused. Cancel any pending
  alarm in case it is just about to go off, and set SIGHUP to be ignored so
  that another HUP in quick succession doesn't clobber the new daemon before it
  gets going. All log files get closed by the close-on-exec flag; however, if
  the exec fails, we need to close the logs. */

  if (sighup_seen)
    {
    log_write(0, LOG_MAIN, "pid %d: SIGHUP received: re-exec daemon",
      getpid());
    close_daemon_sockets(daemon_notifier_fd, fd_polls, listen_socket_count);
    unlink_notifier_socket();
    ALARM_CLR(0);
    signal(SIGHUP, SIG_IGN);
    sighup_argv[0] = exim_path;
    exim_nullstd();
    execv(CS exim_path, (char *const *)sighup_argv);
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "pid %d: exec of %s failed: %s",
      getpid(), exim_path, strerror(errno));
    log_close_all();
    }

  }   /* End of main loop */

/* Control never reaches here */
}

/* vi: aw ai sw=2
*/
/* End of exim_daemon.c */
