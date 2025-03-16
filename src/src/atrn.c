/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2024 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Functions for handling ATRN. */

#include "exim.h"


/* This is called when an Exim server receives an ATRN command.
To be an ATRN-triggered ODMR provider we must accept the command,
swap server/client SMTP roles on the open connection,
and deliver messages for the requested domains. */

int
atrn_handle_provider(uschar ** user_msgp, uschar ** log_msgp)
{
uschar * exp_acl = NULL;
const uschar * list;
int sep = 0, rc;
gstring * g = NULL;
qrunner q = {0};

/*XXX could we used a cached value for "advertised"? */
GET_OPTION("acl_smtp_atrn");
if (acl_smtp_atrn && !atrn_mode
   && (exp_acl = expand_string(acl_smtp_atrn)) && !*exp_acl)
  exp_acl = NULL;
if (!exp_acl || !authenticated_id || sender_address)
  return synprot_error(L_smtp_protocol_error,
    !exp_acl ? 502 : !authenticated_id ? 530 : 503,
    NULL,
    !exp_acl ?		US"ATRN command used when not advertised"
    : !authenticated_id ?	US"ATRN is not permitted without authentication"
    :			US"ATRN is not permitted inside a transaction"
    );

log_write(L_etrn, LOG_MAIN, "ATRN '%s' received from %s",
  smtp_cmd_argument, host_and_ident(FALSE));

if ((rc = acl_check(ACL_WHERE_ATRN, NULL, exp_acl, user_msgp, log_msgp)) != OK)
  return smtp_handle_acl_fail(ACL_WHERE_ATRN, rc, *user_msgp, *log_msgp);

/* ACK the command, record the connection details and turn the line around */

smtp_printf("250 ODMR provider turning line around\r\n", SP_NO_MORE);
atrn_mode = US"P";
atrn_host = string_sprintf("[%s]:%d",
			  sender_host_address, sender_host_port);

if (smtp_out_fd < 0) return FAIL;

#ifndef DISABLE_TLS
if (tls_in.active.sock >= 0)
  tls_state_in_to_out(0, sender_host_address, sender_host_port);
#endif
smtp_fflush();
force_fd(smtp_in_fd, 0);
smtp_in_fd = smtp_out_fd = -1;

/* Set up a onetime queue run, filtering for messages with the
given domains. Later filtering will leave out addresses for other domains
on these messages. */

continue_transport = US"ATRN-provider";
continue_hostname = continue_host_address = sender_host_address;

q.next_tick = time(NULL);
q.run_max = 1;
q.queue_2stage = TRUE;

/* Convert the domainlist to a regex, as the existing queue-selection
facilities support that but not a list */

list = atrn_domains;
for (const uschar * ele; ele = string_nextinlist(&list, &sep, NULL, 0); )
  g = string_append_listele(g, '|', ele);
deliver_selectstring = string_sprintf("@(%Y)", g);
f.deliver_selectstring_regex = TRUE;

single_queue_run(&q , NULL, NULL);
exim_exit(EXIT_SUCCESS);
/*NOTREACHED*/
}



/* This is called when a commandline request is made for an
ODMR customer transaction.  We are given the host to contact
and a (possibly empty) list of domains to request messages for.
We must make an SMTP connection, initially as an SMTP client,
and send an ATRN command.  If accepted, swap SMTP client/server
roles on the open connection and be prepared to accept mail. */

void
atrn_handle_customer(void)
{
address_item * addr =
  deliver_make_addr(string_sprintf("_atrn@%s", atrn_host), FALSE);
int rc;

set_process_info("handling ATRN customer request for host '%s'", atrn_host);

/* Make connection to provider.  We use the verify callout tooling.
Then send the ATRN. */

rcpt_count = 1;
if ((rc = verify_address(addr, -1,
	vopt_atrn | vopt_callout_hold | vopt_callout_recipsender
	| vopt_callout_no_cache,
	30, -1, -1, NULL, NULL, NULL)) != OK)
  exim_exit(EXIT_FAILURE);

if ((rc = smtp_write_atrn(addr, &cutthrough)) == FAIL)
  exim_exit(EXIT_FAILURE);
if (rc == DEFER)
  exim_exit(EXIT_SUCCESS);

/* Flip the connection around */

fflush(stdin);
fflush(stdout);
force_fd(cutthrough.cctx.sock, 0);
(void)dup2(0, 1);

/* Really should re-open the stdio streams on the new fd's to ensure all
the invisible stdio state is proper - but there seems no way to do that.
You cannot assign to std{in,out}, they being macros (per Posix), so fdopen()
is out.  freopen() requires a filesystem name, and we don't have one and cannot
portably invent one for a socket.  We'd have to stop using std{in,out} for
Exim's server side entirely (we use bare fd's for client-side i/o already). */

#ifndef DISABLE_TLS
if (tls_out.active.sock >= 0)
  tls_state_out_to_in(0, cutthrough.host.address, cutthrough.host.port);
#endif

sender_host_address = string_copy(cutthrough.host.address);
sender_host_port = cutthrough.host.port;
release_cutthrough_connection(US"passed for ODMR");

/* Set up for receiving */

smtp_input = TRUE;
f.is_inetd = TRUE;
sender_address = NULL;

#ifdef LOAD_AVG_NEEDS_ROOT
if (queue_only_load >= 0 || smtp_load_reserve >= 0)
  load_average = OS_GETLOADAVG();
#endif

host_build_sender_fullhost();

set_process_info("handling incoming messages from ODMR provider %s",
  sender_fullhost);
return;
}


/* vi: aw ai sw=2
*/
/* End of atrn.c */
