/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* The main code for delivering a message. */


#include "exim.h"


/* Data block for keeping track of subprocesses for parallel remote
delivery. */

typedef struct pardata {
  address_item *addrlist;      /* chain of addresses */
  address_item *addr;          /* next address data expected for */
  pid_t pid;                   /* subprocess pid */
  int fd;                      /* pipe fd for getting result from subprocess */
  int transport_count;         /* returned transport count value */
  BOOL done;                   /* no more data needed */
  uschar *msg;                 /* error message */
  uschar *return_path;         /* return_path for these addresses */
} pardata;

/* Values for the process_recipients variable */

enum { RECIP_ACCEPT, RECIP_IGNORE, RECIP_DEFER,
       RECIP_FAIL, RECIP_FAIL_FILTER, RECIP_FAIL_TIMEOUT,
       RECIP_FAIL_LOOP};

/* Mutually recursive functions for marking addresses done. */

static void child_done(address_item *, uschar *);
static void address_done(address_item *, uschar *);

/* Table for turning base-62 numbers into binary */

static uschar tab62[] =
          {0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0,     /* 0-9 */
           0,10,11,12,13,14,15,16,17,18,19,20,  /* A-K */
          21,22,23,24,25,26,27,28,29,30,31,32,  /* L-W */
          33,34,35, 0, 0, 0, 0, 0,              /* X-Z */
           0,36,37,38,39,40,41,42,43,44,45,46,  /* a-k */
          47,48,49,50,51,52,53,54,55,56,57,58,  /* l-w */
          59,60,61};                            /* x-z */


/*************************************************
*            Local static variables              *
*************************************************/

/* addr_duplicate is global because it needs to be seen from the Envelope-To
writing code. */

static address_item *addr_defer = NULL;
static address_item *addr_failed = NULL;
static address_item *addr_fallback = NULL;
static address_item *addr_local = NULL;
static address_item *addr_new = NULL;
static address_item *addr_remote = NULL;
static address_item *addr_route = NULL;
static address_item *addr_succeed = NULL;
static address_item *addr_dsntmp = NULL;
static address_item *addr_senddsn = NULL;

static FILE *message_log = NULL;
static BOOL update_spool;
static BOOL remove_journal;
static int  parcount = 0;
static pardata *parlist = NULL;
static int  return_count;
static uschar *frozen_info = US"";
static uschar *used_return_path = NULL;

static uschar spoolname[PATH_MAX];



/*************************************************
*             Make a new address item            *
*************************************************/

/* This function gets the store and initializes with default values. The
transport_return value defaults to DEFER, so that any unexpected failure to
deliver does not wipe out the message. The default unique string is set to a
copy of the address, so that its domain can be lowercased.

Argument:
  address     the RFC822 address string
  copy        force a copy of the address

Returns:      a pointer to an initialized address_item
*/

address_item *
deliver_make_addr(uschar *address, BOOL copy)
{
address_item *addr = store_get(sizeof(address_item));
*addr = address_defaults;
if (copy) address = string_copy(address);
addr->address = address;
addr->unique = string_copy(address);
return addr;
}




/*************************************************
*     Set expansion values for an address        *
*************************************************/

/* Certain expansion variables are valid only when handling an address or
address list. This function sets them up or clears the values, according to its
argument.

Arguments:
  addr          the address in question, or NULL to clear values
Returns:        nothing
*/

void
deliver_set_expansions(address_item *addr)
{
if (addr == NULL)
  {
  const uschar ***p = address_expansions;
  while (*p != NULL) **p++ = NULL;
  return;
  }

/* Exactly what gets set depends on whether there is one or more addresses, and
what they contain. These first ones are always set, taking their values from
the first address. */

if (addr->host_list == NULL)
  {
  deliver_host = deliver_host_address = US"";
  deliver_host_port = 0;
  }
else
  {
  deliver_host = addr->host_list->name;
  deliver_host_address = addr->host_list->address;
  deliver_host_port = addr->host_list->port;
  }

deliver_recipients = addr;
deliver_address_data = addr->prop.address_data;
deliver_domain_data = addr->prop.domain_data;
deliver_localpart_data = addr->prop.localpart_data;

/* These may be unset for multiple addresses */

deliver_domain = addr->domain;
self_hostname = addr->self_hostname;

#ifdef EXPERIMENTAL_BRIGHTMAIL
bmi_deliver = 1;    /* deliver by default */
bmi_alt_location = NULL;
bmi_base64_verdict = NULL;
bmi_base64_tracker_verdict = NULL;
#endif

/* If there's only one address we can set everything. */

if (addr->next == NULL)
  {
  address_item *addr_orig;

  deliver_localpart = addr->local_part;
  deliver_localpart_prefix = addr->prefix;
  deliver_localpart_suffix = addr->suffix;

  for (addr_orig = addr; addr_orig->parent != NULL;
    addr_orig = addr_orig->parent);
  deliver_domain_orig = addr_orig->domain;

  /* Re-instate any prefix and suffix in the original local part. In all
  normal cases, the address will have a router associated with it, and we can
  choose the caseful or caseless version accordingly. However, when a system
  filter sets up a pipe, file, or autoreply delivery, no router is involved.
  In this case, though, there won't be any prefix or suffix to worry about. */

  deliver_localpart_orig = (addr_orig->router == NULL)? addr_orig->local_part :
    addr_orig->router->caseful_local_part?
      addr_orig->cc_local_part : addr_orig->lc_local_part;

  /* If there's a parent, make its domain and local part available, and if
  delivering to a pipe or file, or sending an autoreply, get the local
  part from the parent. For pipes and files, put the pipe or file string
  into address_pipe and address_file. */

  if (addr->parent != NULL)
    {
    deliver_domain_parent = addr->parent->domain;
    deliver_localpart_parent = (addr->parent->router == NULL)?
      addr->parent->local_part :
        addr->parent->router->caseful_local_part?
          addr->parent->cc_local_part : addr->parent->lc_local_part;

    /* File deliveries have their own flag because they need to be picked out
    as special more often. */

    if (testflag(addr, af_pfr))
      {
      if (testflag(addr, af_file)) address_file = addr->local_part;
        else if (deliver_localpart[0] == '|') address_pipe = addr->local_part;
      deliver_localpart = addr->parent->local_part;
      deliver_localpart_prefix = addr->parent->prefix;
      deliver_localpart_suffix = addr->parent->suffix;
      }
    }

#ifdef EXPERIMENTAL_BRIGHTMAIL
    /* Set expansion variables related to Brightmail AntiSpam */
    bmi_base64_verdict = bmi_get_base64_verdict(deliver_localpart_orig, deliver_domain_orig);
    bmi_base64_tracker_verdict = bmi_get_base64_tracker_verdict(bmi_base64_verdict);
    /* get message delivery status (0 - don't deliver | 1 - deliver) */
    bmi_deliver = bmi_get_delivery_status(bmi_base64_verdict);
    /* if message is to be delivered, get eventual alternate location */
    if (bmi_deliver == 1) {
      bmi_alt_location = bmi_get_alt_location(bmi_base64_verdict);
    };
#endif

  }

/* For multiple addresses, don't set local part, and leave the domain and
self_hostname set only if it is the same for all of them. It is possible to
have multiple pipe and file addresses, but only when all addresses have routed
to the same pipe or file. */

else
  {
  address_item *addr2;
  if (testflag(addr, af_pfr))
    {
    if (testflag(addr, af_file)) address_file = addr->local_part;
      else if (addr->local_part[0] == '|') address_pipe = addr->local_part;
    }
  for (addr2 = addr->next; addr2 != NULL; addr2 = addr2->next)
    {
    if (deliver_domain != NULL &&
        Ustrcmp(deliver_domain, addr2->domain) != 0)
      deliver_domain = NULL;
    if (self_hostname != NULL && (addr2->self_hostname == NULL ||
        Ustrcmp(self_hostname, addr2->self_hostname) != 0))
      self_hostname = NULL;
    if (deliver_domain == NULL && self_hostname == NULL) break;
    }
  }
}




/*************************************************
*                Open a msglog file              *
*************************************************/

/* This function is used both for normal message logs, and for files in the
msglog directory that are used to catch output from pipes. Try to create the
directory if it does not exist. From release 4.21, normal message logs should
be created when the message is received.

Argument:
  filename  the file name
  mode      the mode required
  error     used for saying what failed

Returns:    a file descriptor, or -1 (with errno set)
*/

static int
open_msglog_file(uschar *filename, int mode, uschar **error)
{
int fd = Uopen(filename, O_WRONLY|O_APPEND|O_CREAT, mode);

if (fd < 0 && errno == ENOENT)
  {
  uschar temp[16];
  sprintf(CS temp, "msglog/%s", message_subdir);
  if (message_subdir[0] == 0) temp[6] = 0;
  (void)directory_make(spool_directory, temp, MSGLOG_DIRECTORY_MODE, TRUE);
  fd = Uopen(filename, O_WRONLY|O_APPEND|O_CREAT, mode);
  }

/* Set the close-on-exec flag and change the owner to the exim uid/gid (this
function is called as root). Double check the mode, because the group setting
doesn't always get set automatically. */

if (fd >= 0)
  {
  (void)fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
  if (fchown(fd, exim_uid, exim_gid) < 0)
    {
    *error = US"chown";
    return -1;
    }
  if (fchmod(fd, mode) < 0)
    {
    *error = US"chmod";
    return -1;
    }
  }
else *error = US"create";

return fd;
}




/*************************************************
*           Write to msglog if required          *
*************************************************/

/* Write to the message log, if configured. This function may also be called
from transports.

Arguments:
  format       a string format

Returns:       nothing
*/

void
deliver_msglog(const char *format, ...)
{
va_list ap;
if (!message_logs) return;
va_start(ap, format);
vfprintf(message_log, format, ap);
fflush(message_log);
va_end(ap);
}




/*************************************************
*            Replicate status for batch          *
*************************************************/

/* When a transport handles a batch of addresses, it may treat them
individually, or it may just put the status in the first one, and return FALSE,
requesting that the status be copied to all the others externally. This is the
replication function. As well as the status, it copies the transport pointer,
which may have changed if appendfile passed the addresses on to a different
transport.

Argument:    pointer to the first address in a chain
Returns:     nothing
*/

static void
replicate_status(address_item *addr)
{
address_item *addr2;
for (addr2 = addr->next; addr2 != NULL; addr2 = addr2->next)
  {
  addr2->transport = addr->transport;
  addr2->transport_return = addr->transport_return;
  addr2->basic_errno = addr->basic_errno;
  addr2->more_errno = addr->more_errno;
  addr2->special_action = addr->special_action;
  addr2->message = addr->message;
  addr2->user_message = addr->user_message;
  }
}



/*************************************************
*              Compare lists of hosts            *
*************************************************/

/* This function is given two pointers to chains of host items, and it yields
TRUE if the lists refer to the same hosts in the same order, except that

(1) Multiple hosts with the same non-negative MX values are permitted to appear
    in different orders. Round-robinning nameservers can cause this to happen.

(2) Multiple hosts with the same negative MX values less than MX_NONE are also
    permitted to appear in different orders. This is caused by randomizing
    hosts lists.

This enables Exim to use a single SMTP transaction for sending to two entirely
different domains that happen to end up pointing at the same hosts.

Arguments:
  one       points to the first host list
  two       points to the second host list

Returns:    TRUE if the lists refer to the same host set
*/

static BOOL
same_hosts(host_item *one, host_item *two)
{
while (one != NULL && two != NULL)
  {
  if (Ustrcmp(one->name, two->name) != 0)
    {
    int mx = one->mx;
    host_item *end_one = one;
    host_item *end_two = two;

    /* Batch up only if there was no MX and the list was not randomized */

    if (mx == MX_NONE) return FALSE;

    /* Find the ends of the shortest sequence of identical MX values */

    while (end_one->next != NULL && end_one->next->mx == mx &&
           end_two->next != NULL && end_two->next->mx == mx)
      {
      end_one = end_one->next;
      end_two = end_two->next;
      }

    /* If there aren't any duplicates, there's no match. */

    if (end_one == one) return FALSE;

    /* For each host in the 'one' sequence, check that it appears in the 'two'
    sequence, returning FALSE if not. */

    for (;;)
      {
      host_item *hi;
      for (hi = two; hi != end_two->next; hi = hi->next)
        if (Ustrcmp(one->name, hi->name) == 0) break;
      if (hi == end_two->next) return FALSE;
      if (one == end_one) break;
      one = one->next;
      }

    /* All the hosts in the 'one' sequence were found in the 'two' sequence.
    Ensure both are pointing at the last host, and carry on as for equality. */

    two = end_two;
    }

  /* Hosts matched */

  one = one->next;
  two = two->next;
  }

/* True if both are NULL */

return (one == two);
}



/*************************************************
*              Compare header lines              *
*************************************************/

/* This function is given two pointers to chains of header items, and it yields
TRUE if they are the same header texts in the same order.

Arguments:
  one       points to the first header list
  two       points to the second header list

Returns:    TRUE if the lists refer to the same header set
*/

static BOOL
same_headers(header_line *one, header_line *two)
{
for (;;)
  {
  if (one == two) return TRUE;   /* Includes the case where both NULL */
  if (one == NULL || two == NULL) return FALSE;
  if (Ustrcmp(one->text, two->text) != 0) return FALSE;
  one = one->next;
  two = two->next;
  }
}



/*************************************************
*            Compare string settings             *
*************************************************/

/* This function is given two pointers to strings, and it returns
TRUE if they are the same pointer, or if the two strings are the same.

Arguments:
  one       points to the first string
  two       points to the second string

Returns:    TRUE or FALSE
*/

static BOOL
same_strings(uschar *one, uschar *two)
{
if (one == two) return TRUE;   /* Includes the case where both NULL */
if (one == NULL || two == NULL) return FALSE;
return (Ustrcmp(one, two) == 0);
}



/*************************************************
*        Compare uid/gid for addresses           *
*************************************************/

/* This function is given a transport and two addresses. It yields TRUE if the
uid/gid/initgroups settings for the two addresses are going to be the same when
they are delivered.

Arguments:
  tp            the transort
  addr1         the first address
  addr2         the second address

Returns:        TRUE or FALSE
*/

static BOOL
same_ugid(transport_instance *tp, address_item *addr1, address_item *addr2)
{
if (!tp->uid_set && tp->expand_uid == NULL && !tp->deliver_as_creator)
  {
  if (testflag(addr1, af_uid_set) != testflag(addr2, af_gid_set) ||
       (testflag(addr1, af_uid_set) &&
         (addr1->uid != addr2->uid ||
          testflag(addr1, af_initgroups) != testflag(addr2, af_initgroups))))
    return FALSE;
  }

if (!tp->gid_set && tp->expand_gid == NULL)
  {
  if (testflag(addr1, af_gid_set) != testflag(addr2, af_gid_set) ||
     (testflag(addr1, af_gid_set) && addr1->gid != addr2->gid))
    return FALSE;
  }

return TRUE;
}




/*************************************************
*      Record that an address is complete        *
*************************************************/

/* This function records that an address is complete. This is straightforward
for most addresses, where the unique address is just the full address with the
domain lower cased. For homonyms (addresses that are the same as one of their
ancestors) their are complications. Their unique addresses have \x\ prepended
(where x = 0, 1, 2...), so that de-duplication works correctly for siblings and
cousins.

Exim used to record the unique addresses of homonyms as "complete". This,
however, fails when the pattern of redirection varies over time (e.g. if taking
unseen copies at only some times of day) because the prepended numbers may vary
from one delivery run to the next. This problem is solved by never recording
prepended unique addresses as complete. Instead, when a homonymic address has
actually been delivered via a transport, we record its basic unique address
followed by the name of the transport. This is checked in subsequent delivery
runs whenever an address is routed to a transport.

If the completed address is a top-level one (has no parent, which means it
cannot be homonymic) we also add the original address to the non-recipients
tree, so that it gets recorded in the spool file and therefore appears as
"done" in any spool listings. The original address may differ from the unique
address in the case of the domain.

Finally, this function scans the list of duplicates, marks as done any that
match this address, and calls child_done() for their ancestors.

Arguments:
  addr        address item that has been completed
  now         current time as a string

Returns:      nothing
*/

static void
address_done(address_item *addr, uschar *now)
{
address_item *dup;

update_spool = TRUE;        /* Ensure spool gets updated */

/* Top-level address */

if (addr->parent == NULL)
  {
  tree_add_nonrecipient(addr->unique);
  tree_add_nonrecipient(addr->address);
  }

/* Homonymous child address */

else if (testflag(addr, af_homonym))
  {
  if (addr->transport != NULL)
    {
    tree_add_nonrecipient(
      string_sprintf("%s/%s", addr->unique + 3, addr->transport->name));
    }
  }

/* Non-homonymous child address */

else tree_add_nonrecipient(addr->unique);

/* Check the list of duplicate addresses and ensure they are now marked
done as well. */

for (dup = addr_duplicate; dup != NULL; dup = dup->next)
  {
  if (Ustrcmp(addr->unique, dup->unique) == 0)
    {
    tree_add_nonrecipient(dup->unique);
    child_done(dup, now);
    }
  }
}




/*************************************************
*      Decrease counts in parents and mark done  *
*************************************************/

/* This function is called when an address is complete. If there is a parent
address, its count of children is decremented. If there are still other
children outstanding, the function exits. Otherwise, if the count has become
zero, address_done() is called to mark the parent and its duplicates complete.
Then loop for any earlier ancestors.

Arguments:
  addr      points to the completed address item
  now       the current time as a string, for writing to the message log

Returns:    nothing
*/

static void
child_done(address_item *addr, uschar *now)
{
address_item *aa;
while (addr->parent != NULL)
  {
  addr = addr->parent;
  if ((addr->child_count -= 1) > 0) return;   /* Incomplete parent */
  address_done(addr, now);

  /* Log the completion of all descendents only when there is no ancestor with
  the same original address. */

  for (aa = addr->parent; aa != NULL; aa = aa->parent)
    if (Ustrcmp(aa->address, addr->address) == 0) break;
  if (aa != NULL) continue;

  deliver_msglog("%s %s: children all complete\n", now, addr->address);
  DEBUG(D_deliver) debug_printf("%s: children all complete\n", addr->address);
  }
}




static uschar *
d_hostlog(uschar * s, int * sizep, int * ptrp, address_item * addr)
{
  s = string_append(s, sizep, ptrp, 5, US" H=", addr->host_used->name,
    US" [", addr->host_used->address, US"]");
  if ((log_extra_selector & LX_outgoing_port) != 0)
    s = string_append(s, sizep, ptrp, 2, US":", string_sprintf("%d",
      addr->host_used->port));
  return s;
}

#ifdef SUPPORT_TLS
static uschar *
d_tlslog(uschar * s, int * sizep, int * ptrp, address_item * addr)
{
  if ((log_extra_selector & LX_tls_cipher) != 0 && addr->cipher != NULL)
    s = string_append(s, sizep, ptrp, 2, US" X=", addr->cipher);
  if ((log_extra_selector & LX_tls_certificate_verified) != 0 &&
       addr->cipher != NULL)
    s = string_append(s, sizep, ptrp, 2, US" CV=",
      testflag(addr, af_cert_verified)
      ?
#ifdef EXPERIMENTAL_DANE
        testflag(addr, af_dane_verified)
      ? "dane"
      :
#endif
        "yes"
      : "no");
  if ((log_extra_selector & LX_tls_peerdn) != 0 && addr->peerdn != NULL)
    s = string_append(s, sizep, ptrp, 3, US" DN=\"",
      string_printing(addr->peerdn), US"\"");
  return s;
}
#endif




#ifdef EXPERIMENTAL_EVENT
uschar *
event_raise(uschar * action, const uschar * event, uschar * ev_data)
{
uschar * s;
if (action)
  {
  DEBUG(D_deliver)
    debug_printf("Event(%s): event_action=|%s| delivery_IP=%s\n",
      event,
      action, deliver_host_address);

  event_name = event;
  event_data = ev_data;

  if (!(s = expand_string(action)) && *expand_string_message)
    log_write(0, LOG_MAIN|LOG_PANIC,
      "failed to expand event_action %s in %s: %s\n",
      event, transport_name, expand_string_message);

  event_name = event_data = NULL;

  /* If the expansion returns anything but an empty string, flag for
  the caller to modify his normal processing
  */
  if (s && *s)
    {
    DEBUG(D_deliver)
      debug_printf("Event(%s): event_action returned \"%s\"\n", event, s);
    return s;
    }
  }
return NULL;
}

static void
msg_event_raise(const uschar * event, const address_item * addr)
{
const uschar * save_domain = deliver_domain;
uschar * save_local =  deliver_localpart;
const uschar * save_host = deliver_host;

if (!addr->transport)
  return;

router_name =    addr->router ? addr->router->name : NULL;
transport_name = addr->transport->name;
deliver_domain = addr->domain;
deliver_localpart = addr->local_part;
deliver_host =   addr->host_used ? addr->host_used->name : NULL;

(void) event_raise(addr->transport->event_action, event,
	  addr->host_used || Ustrcmp(addr->transport->driver_name, "lmtp") == 0
	  ? addr->message : NULL);

deliver_host =      save_host;
deliver_localpart = save_local;
deliver_domain =    save_domain;
router_name = transport_name = NULL;
}
#endif	/*EXPERIMENTAL_EVENT*/



/* If msg is NULL this is a delivery log and logchar is used. Otherwise
this is a nonstandard call; no two-character delivery flag is written
but sender-host and sender are prefixed and "msg" is inserted in the log line.

Arguments:
  flags		passed to log_write()
*/
void
delivery_log(int flags, address_item * addr, int logchar, uschar * msg)
{
uschar *log_address;
int size = 256;         /* Used for a temporary, */
int ptr = 0;            /* expanding buffer, for */
uschar *s;              /* building log lines;   */
void *reset_point;      /* released afterwards.  */

/* Log the delivery on the main log. We use an extensible string to build up
the log line, and reset the store afterwards. Remote deliveries should always
have a pointer to the host item that succeeded; local deliveries can have a
pointer to a single host item in their host list, for use by the transport. */

#ifdef EXPERIMENTAL_EVENT
  /* presume no successful remote delivery */
  lookup_dnssec_authenticated = NULL;
#endif

s = reset_point = store_get(size);

log_address = string_log_address(addr, (log_write_selector & L_all_parents) != 0, TRUE);
if (msg)
  s = string_append(s, &size, &ptr, 3, host_and_ident(TRUE), US" ", log_address);
else
  {
  s[ptr++] = logchar;
  s = string_append(s, &size, &ptr, 2, US"> ", log_address);
  }

if (log_extra_selector & LX_incoming_interface  &&  sending_ip_address)
  s = string_append(s, &size, &ptr, 3, US" I=[", sending_ip_address, US"]");
  /* for the port:  string_sprintf("%d", sending_port) */

if ((log_extra_selector & LX_sender_on_delivery) != 0  ||  msg)
  s = string_append(s, &size, &ptr, 3, US" F=<",
#ifdef EXPERIMENTAL_INTERNATIONAL
    testflag(addr, af_utf8_downcvt)
    ? string_address_utf8_to_alabel(sender_address, NULL)
    :
#endif
      sender_address,
  US">");

#ifdef EXPERIMENTAL_SRS
if(addr->prop.srs_sender)
  s = string_append(s, &size, &ptr, 3, US" SRS=<", addr->prop.srs_sender, US">");
#endif

/* You might think that the return path must always be set for a successful
delivery; indeed, I did for some time, until this statement crashed. The case
when it is not set is for a delivery to /dev/null which is optimised by not
being run at all. */

if (used_return_path != NULL &&
      (log_extra_selector & LX_return_path_on_delivery) != 0)
  s = string_append(s, &size, &ptr, 3, US" P=<", used_return_path, US">");

if (msg)
  s = string_append(s, &size, &ptr, 2, US" ", msg);

/* For a delivery from a system filter, there may not be a router */
if (addr->router != NULL)
  s = string_append(s, &size, &ptr, 2, US" R=", addr->router->name);

s = string_append(s, &size, &ptr, 2, US" T=", addr->transport->name);

if ((log_extra_selector & LX_delivery_size) != 0)
  s = string_append(s, &size, &ptr, 2, US" S=",
    string_sprintf("%d", transport_count));

/* Local delivery */

if (addr->transport->info->local)
  {
  if (addr->host_list)
    s = string_append(s, &size, &ptr, 2, US" H=", addr->host_list->name);
  if (addr->shadow_message != NULL)
    s = string_cat(s, &size, &ptr, addr->shadow_message,
      Ustrlen(addr->shadow_message));
  }

/* Remote delivery */

else
  {
  if (addr->host_used)
    {
    s = d_hostlog(s, &size, &ptr, addr);
    if (continue_sequence > 1)
      s = string_cat(s, &size, &ptr, US"*", 1);

#ifdef EXPERIMENTAL_EVENT
    deliver_host_address = addr->host_used->address;
    deliver_host_port =    addr->host_used->port;
    deliver_host =         addr->host_used->name;

    /* DNS lookup status */
    lookup_dnssec_authenticated = addr->host_used->dnssec==DS_YES ? US"yes"
			      : addr->host_used->dnssec==DS_NO ? US"no"
			      : NULL;
#endif
    }

#ifdef SUPPORT_TLS
  s = d_tlslog(s, &size, &ptr, addr);
#endif

  if (addr->authenticator)
    {
    s = string_append(s, &size, &ptr, 2, US" A=", addr->authenticator);
    if (addr->auth_id)
      {
      s = string_append(s, &size, &ptr, 2, US":", addr->auth_id);
      if (log_extra_selector & LX_smtp_mailauth  &&  addr->auth_sndr)
        s = string_append(s, &size, &ptr, 2, US":", addr->auth_sndr);
      }
    }

#ifndef DISABLE_PRDR
  if (addr->flags & af_prdr_used)
    s = string_append(s, &size, &ptr, 1, US" PRDR");
#endif
  }

/* confirmation message (SMTP (host_used) and LMTP (driver_name)) */

if (log_extra_selector & LX_smtp_confirmation &&
    addr->message &&
    (addr->host_used || Ustrcmp(addr->transport->driver_name, "lmtp") == 0))
  {
  unsigned i;
  unsigned lim = big_buffer_size < 1024 ? big_buffer_size : 1024;
  uschar *p = big_buffer;
  uschar *ss = addr->message;
  *p++ = '\"';
  for (i = 0; i < lim && ss[i] != 0; i++)	/* limit logged amount */
    {
    if (ss[i] == '\"' || ss[i] == '\\') *p++ = '\\'; /* quote \ and " */
    *p++ = ss[i];
    }
  *p++ = '\"';
  *p = 0;
  s = string_append(s, &size, &ptr, 2, US" C=", big_buffer);
  }

/* Time on queue and actual time taken to deliver */

if ((log_extra_selector & LX_queue_time) != 0)
  s = string_append(s, &size, &ptr, 2, US" QT=",
    readconf_printtime( (int) ((long)time(NULL) - (long)received_time)) );

if ((log_extra_selector & LX_deliver_time) != 0)
  s = string_append(s, &size, &ptr, 2, US" DT=",
    readconf_printtime(addr->more_errno));

/* string_cat() always leaves room for the terminator. Release the
store we used to build the line after writing it. */

s[ptr] = 0;
log_write(0, flags, "%s", s);

#ifdef EXPERIMENTAL_EVENT
if (!msg) msg_event_raise(US"msg:delivery", addr);
#endif

store_reset(reset_point);
return;
}



/*************************************************
*    Actions at the end of handling an address   *
*************************************************/

/* This is a function for processing a single address when all that can be done
with it has been done.

Arguments:
  addr         points to the address block
  result       the result of the delivery attempt
  logflags     flags for log_write() (LOG_MAIN and/or LOG_PANIC)
  driver_type  indicates which type of driver (transport, or router) was last
                 to process the address
  logchar      '=' or '-' for use when logging deliveries with => or ->

Returns:       nothing
*/

static void
post_process_one(address_item *addr, int result, int logflags, int driver_type,
  int logchar)
{
uschar *now = tod_stamp(tod_log);
uschar *driver_kind = NULL;
uschar *driver_name = NULL;
uschar *log_address;

int size = 256;         /* Used for a temporary, */
int ptr = 0;            /* expanding buffer, for */
uschar *s;              /* building log lines;   */
void *reset_point;      /* released afterwards.  */

DEBUG(D_deliver) debug_printf("post-process %s (%d)\n", addr->address, result);

/* Set up driver kind and name for logging. Disable logging if the router or
transport has disabled it. */

if (driver_type == DTYPE_TRANSPORT)
  {
  if (addr->transport != NULL)
    {
    driver_name = addr->transport->name;
    driver_kind = US" transport";
    disable_logging = addr->transport->disable_logging;
    }
  else driver_kind = US"transporting";
  }
else if (driver_type == DTYPE_ROUTER)
  {
  if (addr->router != NULL)
    {
    driver_name = addr->router->name;
    driver_kind = US" router";
    disable_logging = addr->router->disable_logging;
    }
  else driver_kind = US"routing";
  }

/* If there's an error message set, ensure that it contains only printing
characters - it should, but occasionally things slip in and this at least
stops the log format from getting wrecked. We also scan the message for an LDAP
expansion item that has a password setting, and flatten the password. This is a
fudge, but I don't know a cleaner way of doing this. (If the item is badly
malformed, it won't ever have gone near LDAP.) */

if (addr->message != NULL)
  {
  const uschar * s = string_printing(addr->message);
  if (s != addr->message)
    addr->message = US s;
    /* deconst cast ok as string_printing known to have alloc'n'copied */
  if (((Ustrstr(addr->message, "failed to expand") != NULL) || (Ustrstr(addr->message, "expansion of ") != NULL)) &&
      (Ustrstr(addr->message, "mysql") != NULL ||
       Ustrstr(addr->message, "pgsql") != NULL ||
#ifdef EXPERIMENTAL_REDIS
       Ustrstr(addr->message, "redis") != NULL ||
#endif
       Ustrstr(addr->message, "sqlite") != NULL ||
       Ustrstr(addr->message, "ldap:") != NULL ||
       Ustrstr(addr->message, "ldapdn:") != NULL ||
       Ustrstr(addr->message, "ldapm:") != NULL))
    {
      addr->message = string_sprintf("Temporary internal error");
    }
  }

/* If we used a transport that has one of the "return_output" options set, and
if it did in fact generate some output, then for return_output we treat the
message as failed if it was not already set that way, so that the output gets
returned to the sender, provided there is a sender to send it to. For
return_fail_output, do this only if the delivery failed. Otherwise we just
unlink the file, and remove the name so that if the delivery failed, we don't
try to send back an empty or unwanted file. The log_output options operate only
on a non-empty file.

In any case, we close the message file, because we cannot afford to leave a
file-descriptor for one address while processing (maybe very many) others. */

if (addr->return_file >= 0 && addr->return_filename != NULL)
  {
  BOOL return_output = FALSE;
  struct stat statbuf;
  (void)EXIMfsync(addr->return_file);

  /* If there is no output, do nothing. */

  if (fstat(addr->return_file, &statbuf) == 0 && statbuf.st_size > 0)
    {
    transport_instance *tb = addr->transport;

    /* Handle logging options */

    if (tb->log_output || (result == FAIL && tb->log_fail_output) ||
                          (result == DEFER && tb->log_defer_output))
      {
      uschar *s;
      FILE *f = Ufopen(addr->return_filename, "rb");
      if (f == NULL)
        log_write(0, LOG_MAIN|LOG_PANIC, "failed to open %s to log output "
          "from %s transport: %s", addr->return_filename, tb->name,
          strerror(errno));
      else
        {
        s = US Ufgets(big_buffer, big_buffer_size, f);
        if (s != NULL)
          {
          uschar *p = big_buffer + Ustrlen(big_buffer);
	  const uschar * sp;
          while (p > big_buffer && isspace(p[-1])) p--;
          *p = 0;
          sp = string_printing(big_buffer);
          log_write(0, LOG_MAIN, "<%s>: %s transport output: %s",
            addr->address, tb->name, sp);
          }
        (void)fclose(f);
        }
      }

    /* Handle returning options, but only if there is an address to return
    the text to. */

    if (sender_address[0] != 0 || addr->prop.errors_address != NULL)
      {
      if (tb->return_output)
        {
        addr->transport_return = result = FAIL;
        if (addr->basic_errno == 0 && addr->message == NULL)
          addr->message = US"return message generated";
        return_output = TRUE;
        }
      else
        if (tb->return_fail_output && result == FAIL) return_output = TRUE;
      }
    }

  /* Get rid of the file unless it might be returned, but close it in
  all cases. */

  if (!return_output)
    {
    Uunlink(addr->return_filename);
    addr->return_filename = NULL;
    addr->return_file = -1;
    }

  (void)close(addr->return_file);
  }

/* The success case happens only after delivery by a transport. */

if (result == OK)
  {
  addr->next = addr_succeed;
  addr_succeed = addr;

  /* Call address_done() to ensure that we don't deliver to this address again,
  and write appropriate things to the message log. If it is a child address, we
  call child_done() to scan the ancestors and mark them complete if this is the
  last child to complete. */

  address_done(addr, now);
  DEBUG(D_deliver) debug_printf("%s delivered\n", addr->address);

  if (addr->parent == NULL)
    deliver_msglog("%s %s: %s%s succeeded\n", now, addr->address,
      driver_name, driver_kind);
  else
    {
    deliver_msglog("%s %s <%s>: %s%s succeeded\n", now, addr->address,
      addr->parent->address, driver_name, driver_kind);
    child_done(addr, now);
    }

  /* Certificates for logging (via events) */
#ifdef SUPPORT_TLS
  tls_out.ourcert = addr->ourcert;
  addr->ourcert = NULL;
  tls_out.peercert = addr->peercert;
  addr->peercert = NULL;

  tls_out.cipher = addr->cipher;
  tls_out.peerdn = addr->peerdn;
  tls_out.ocsp = addr->ocsp;
# ifdef EXPERIMENTAL_DANE
  tls_out.dane_verified = testflag(addr, af_dane_verified);
# endif
#endif

  delivery_log(LOG_MAIN, addr, logchar, NULL);

#ifdef SUPPORT_TLS
  tls_free_cert(&tls_out.ourcert);
  tls_free_cert(&tls_out.peercert);
  tls_out.cipher = NULL;
  tls_out.peerdn = NULL;
  tls_out.ocsp = OCSP_NOT_REQ;
# ifdef EXPERIMENTAL_DANE
  tls_out.dane_verified = FALSE;
# endif
#endif
  }


/* Soft failure, or local delivery process failed; freezing may be
requested. */

else if (result == DEFER || result == PANIC)
  {
  if (result == PANIC) logflags |= LOG_PANIC;

  /* This puts them on the chain in reverse order. Do not change this, because
  the code for handling retries assumes that the one with the retry
  information is last. */

  addr->next = addr_defer;
  addr_defer = addr;

  /* The only currently implemented special action is to freeze the
  message. Logging of this is done later, just before the -H file is
  updated. */

  if (addr->special_action == SPECIAL_FREEZE)
    {
    deliver_freeze = TRUE;
    deliver_frozen_at = time(NULL);
    update_spool = TRUE;
    }

  /* If doing a 2-stage queue run, we skip writing to either the message
  log or the main log for SMTP defers. */

  if (!queue_2stage || addr->basic_errno != 0)
    {
    uschar ss[32];

    /* For errors of the type "retry time not reached" (also remotes skipped
    on queue run), logging is controlled by L_retry_defer. Note that this kind
    of error number is negative, and all the retry ones are less than any
    others. */

    unsigned int use_log_selector = (addr->basic_errno <= ERRNO_RETRY_BASE)?
      L_retry_defer : 0;

    /* Build up the line that is used for both the message log and the main
    log. */

    s = reset_point = store_get(size);

    /* Create the address string for logging. Must not do this earlier, because
    an OK result may be changed to FAIL when a pipe returns text. */

    log_address = string_log_address(addr,
      (log_write_selector & L_all_parents) != 0, result == OK);

    s = string_cat(s, &size, &ptr, log_address, Ustrlen(log_address));

    /* Either driver_name contains something and driver_kind contains
    " router" or " transport" (note the leading space), or driver_name is
    a null string and driver_kind contains "routing" without the leading
    space, if all routing has been deferred. When a domain has been held,
    so nothing has been done at all, both variables contain null strings. */

    if (driver_name == NULL)
      {
      if (driver_kind != NULL)
        s = string_append(s, &size, &ptr, 2, US" ", driver_kind);
      }
     else
      {
      if (driver_kind[1] == 't' && addr->router != NULL)
        s = string_append(s, &size, &ptr, 2, US" R=", addr->router->name);
      Ustrcpy(ss, " ?=");
      ss[1] = toupper(driver_kind[1]);
      s = string_append(s, &size, &ptr, 2, ss, driver_name);
      }

    sprintf(CS ss, " defer (%d)", addr->basic_errno);
    s = string_cat(s, &size, &ptr, ss, Ustrlen(ss));

    if (addr->basic_errno > 0)
      s = string_append(s, &size, &ptr, 2, US": ",
        US strerror(addr->basic_errno));

    if (addr->host_used)
      s = string_append(s, &size, &ptr, 5,
			US" H=", addr->host_used->name,
			US" [",  addr->host_used->address, US"]");

    if (addr->message != NULL)
      s = string_append(s, &size, &ptr, 2, US": ", addr->message);

    s[ptr] = 0;

    /* Log the deferment in the message log, but don't clutter it
    up with retry-time defers after the first delivery attempt. */

    if (deliver_firsttime || addr->basic_errno > ERRNO_RETRY_BASE)
      deliver_msglog("%s %s\n", now, s);

    /* Write the main log and reset the store */

    log_write(use_log_selector, logflags, "== %s", s);
    store_reset(reset_point);
    }
  }


/* Hard failure. If there is an address to which an error message can be sent,
put this address on the failed list. If not, put it on the deferred list and
freeze the mail message for human attention. The latter action can also be
explicitly requested by a router or transport. */

else
  {
  /* If this is a delivery error, or a message for which no replies are
  wanted, and the message's age is greater than ignore_bounce_errors_after,
  force the af_ignore_error flag. This will cause the address to be discarded
  later (with a log entry). */

  if (sender_address[0] == 0 && message_age >= ignore_bounce_errors_after)
    setflag(addr, af_ignore_error);

  /* Freeze the message if requested, or if this is a bounce message (or other
  message with null sender) and this address does not have its own errors
  address. However, don't freeze if errors are being ignored. The actual code
  to ignore occurs later, instead of sending a message. Logging of freezing
  occurs later, just before writing the -H file. */

  if (!testflag(addr, af_ignore_error) &&
      (addr->special_action == SPECIAL_FREEZE ||
        (sender_address[0] == 0 && addr->prop.errors_address == NULL)
      ))
    {
    frozen_info = (addr->special_action == SPECIAL_FREEZE)? US"" :
      (sender_local && !local_error_message)?
        US" (message created with -f <>)" : US" (delivery error message)";
    deliver_freeze = TRUE;
    deliver_frozen_at = time(NULL);
    update_spool = TRUE;

    /* The address is put on the defer rather than the failed queue, because
    the message is being retained. */

    addr->next = addr_defer;
    addr_defer = addr;
    }

  /* Don't put the address on the nonrecipients tree yet; wait until an
  error message has been successfully sent. */

  else
    {
    addr->next = addr_failed;
    addr_failed = addr;
    }

  /* Build up the log line for the message and main logs */

  s = reset_point = store_get(size);

  /* Create the address string for logging. Must not do this earlier, because
  an OK result may be changed to FAIL when a pipe returns text. */

  log_address = string_log_address(addr,
    (log_write_selector & L_all_parents) != 0, result == OK);

  s = string_cat(s, &size, &ptr, log_address, Ustrlen(log_address));

  if ((log_extra_selector & LX_sender_on_delivery) != 0)
    s = string_append(s, &size, &ptr, 3, US" F=<", sender_address, US">");

  /* Return path may not be set if no delivery actually happened */

  if (used_return_path != NULL &&
      (log_extra_selector & LX_return_path_on_delivery) != 0)
    s = string_append(s, &size, &ptr, 3, US" P=<", used_return_path, US">");

  if (addr->router != NULL)
    s = string_append(s, &size, &ptr, 2, US" R=", addr->router->name);
  if (addr->transport != NULL)
    s = string_append(s, &size, &ptr, 2, US" T=", addr->transport->name);

  if (addr->host_used != NULL)
    s = d_hostlog(s, &size, &ptr, addr);

#ifdef SUPPORT_TLS
  s = d_tlslog(s, &size, &ptr, addr);
#endif

  if (addr->basic_errno > 0)
    s = string_append(s, &size, &ptr, 2, US": ",
      US strerror(addr->basic_errno));

  if (addr->message != NULL)
    s = string_append(s, &size, &ptr, 2, US": ", addr->message);

  s[ptr] = 0;

  /* Do the logging. For the message log, "routing failed" for those cases,
  just to make it clearer. */

  if (driver_name == NULL)
    deliver_msglog("%s %s failed for %s\n", now, driver_kind, s);
  else
    deliver_msglog("%s %s\n", now, s);

  log_write(0, LOG_MAIN, "** %s", s);

#ifdef EXPERIMENTAL_EVENT
  msg_event_raise(US"msg:fail:delivery", addr);
#endif

  store_reset(reset_point);
  }

/* Ensure logging is turned on again in all cases */

disable_logging = FALSE;
}




/*************************************************
*            Address-independent error           *
*************************************************/

/* This function is called when there's an error that is not dependent on a
particular address, such as an expansion string failure. It puts the error into
all the addresses in a batch, logs the incident on the main and panic logs, and
clears the expansions. It is mostly called from local_deliver(), but can be
called for a remote delivery via findugid().

Arguments:
  logit        TRUE if (MAIN+PANIC) logging required
  addr         the first of the chain of addresses
  code         the error code
  format       format string for error message, or NULL if already set in addr
  ...          arguments for the format

Returns:       nothing
*/

static void
common_error(BOOL logit, address_item *addr, int code, uschar *format, ...)
{
address_item *addr2;
addr->basic_errno = code;

if (format != NULL)
  {
  va_list ap;
  uschar buffer[512];
  va_start(ap, format);
  if (!string_vformat(buffer, sizeof(buffer), CS format, ap))
    log_write(0, LOG_MAIN|LOG_PANIC_DIE,
      "common_error expansion was longer than " SIZE_T_FMT, sizeof(buffer));
  va_end(ap);
  addr->message = string_copy(buffer);
  }

for (addr2 = addr->next; addr2 != NULL; addr2 = addr2->next)
  {
  addr2->basic_errno = code;
  addr2->message = addr->message;
  }

if (logit) log_write(0, LOG_MAIN|LOG_PANIC, "%s", addr->message);
deliver_set_expansions(NULL);
}




/*************************************************
*         Check a "never users" list             *
*************************************************/

/* This function is called to check whether a uid is on one of the two "never
users" lists.

Arguments:
  uid         the uid to be checked
  nusers      the list to be scanned; the first item in the list is the count

Returns:      TRUE if the uid is on the list
*/

static BOOL
check_never_users(uid_t uid, uid_t *nusers)
{
int i;
if (nusers == NULL) return FALSE;
for (i = 1; i <= (int)(nusers[0]); i++) if (nusers[i] == uid) return TRUE;
return FALSE;
}



/*************************************************
*          Find uid and gid for a transport      *
*************************************************/

/* This function is called for both local and remote deliveries, to find the
uid/gid under which to run the delivery. The values are taken preferentially
from the transport (either explicit or deliver_as_creator), then from the
address (i.e. the router), and if nothing is set, the exim uid/gid are used. If
the resulting uid is on the "never_users" or the "fixed_never_users" list, a
panic error is logged, and the function fails (which normally leads to delivery
deferral).

Arguments:
  addr         the address (possibly a chain)
  tp           the transport
  uidp         pointer to uid field
  gidp         pointer to gid field
  igfp         pointer to the use_initgroups field

Returns:       FALSE if failed - error has been set in address(es)
*/

static BOOL
findugid(address_item *addr, transport_instance *tp, uid_t *uidp, gid_t *gidp,
  BOOL *igfp)
{
uschar *nuname = NULL;
BOOL gid_set = FALSE;

/* Default initgroups flag comes from the transport */

*igfp = tp->initgroups;

/* First see if there's a gid on the transport, either fixed or expandable.
The expanding function always logs failure itself. */

if (tp->gid_set)
  {
  *gidp = tp->gid;
  gid_set = TRUE;
  }
else if (tp->expand_gid != NULL)
  {
  if (route_find_expanded_group(tp->expand_gid, tp->name, US"transport", gidp,
    &(addr->message))) gid_set = TRUE;
  else
    {
    common_error(FALSE, addr, ERRNO_GIDFAIL, NULL);
    return FALSE;
    }
  }

/* If the transport did not set a group, see if the router did. */

if (!gid_set && testflag(addr, af_gid_set))
  {
  *gidp = addr->gid;
  gid_set = TRUE;
  }

/* Pick up a uid from the transport if one is set. */

if (tp->uid_set) *uidp = tp->uid;

/* Otherwise, try for an expandable uid field. If it ends up as a numeric id,
it does not provide a passwd value from which a gid can be taken. */

else if (tp->expand_uid != NULL)
  {
  struct passwd *pw;
  if (!route_find_expanded_user(tp->expand_uid, tp->name, US"transport", &pw,
       uidp, &(addr->message)))
    {
    common_error(FALSE, addr, ERRNO_UIDFAIL, NULL);
    return FALSE;
    }
  if (!gid_set && pw != NULL)
    {
    *gidp = pw->pw_gid;
    gid_set = TRUE;
    }
  }

/* If the transport doesn't set the uid, test the deliver_as_creator flag. */

else if (tp->deliver_as_creator)
  {
  *uidp = originator_uid;
  if (!gid_set)
    {
    *gidp = originator_gid;
    gid_set = TRUE;
    }
  }

/* Otherwise see if the address specifies the uid and if so, take it and its
initgroups flag. */

else if (testflag(addr, af_uid_set))
  {
  *uidp = addr->uid;
  *igfp = testflag(addr, af_initgroups);
  }

/* Nothing has specified the uid - default to the Exim user, and group if the
gid is not set. */

else
  {
  *uidp = exim_uid;
  if (!gid_set)
    {
    *gidp = exim_gid;
    gid_set = TRUE;
    }
  }

/* If no gid is set, it is a disaster. We default to the Exim gid only if
defaulting to the Exim uid. In other words, if the configuration has specified
a uid, it must also provide a gid. */

if (!gid_set)
  {
  common_error(TRUE, addr, ERRNO_GIDFAIL, US"User set without group for "
    "%s transport", tp->name);
  return FALSE;
  }

/* Check that the uid is not on the lists of banned uids that may not be used
for delivery processes. */

if (check_never_users(*uidp, never_users))
  nuname = US"never_users";
else if (check_never_users(*uidp, fixed_never_users))
  nuname = US"fixed_never_users";

if (nuname != NULL)
  {
  common_error(TRUE, addr, ERRNO_UIDFAIL, US"User %ld set for %s transport "
    "is on the %s list", (long int)(*uidp), tp->name, nuname);
  return FALSE;
  }

/* All is well */

return TRUE;
}




/*************************************************
*   Check the size of a message for a transport  *
*************************************************/

/* Checks that the message isn't too big for the selected transport.
This is called only when it is known that the limit is set.

Arguments:
  tp          the transport
  addr        the (first) address being delivered

Returns:      OK
              DEFER   expansion failed or did not yield an integer
              FAIL    message too big
*/

int
check_message_size(transport_instance *tp, address_item *addr)
{
int rc = OK;
int size_limit;

deliver_set_expansions(addr);
size_limit = expand_string_integer(tp->message_size_limit, TRUE);
deliver_set_expansions(NULL);

if (expand_string_message != NULL)
  {
  rc = DEFER;
  if (size_limit == -1)
    addr->message = string_sprintf("failed to expand message_size_limit "
      "in %s transport: %s", tp->name, expand_string_message);
  else
    addr->message = string_sprintf("invalid message_size_limit "
      "in %s transport: %s", tp->name, expand_string_message);
  }
else if (size_limit > 0 && message_size > size_limit)
  {
  rc = FAIL;
  addr->message =
    string_sprintf("message is too big (transport limit = %d)",
      size_limit);
  }

return rc;
}



/*************************************************
*  Transport-time check for a previous delivery  *
*************************************************/

/* Check that this base address hasn't previously been delivered to its routed
transport. If it has been delivered, mark it done. The check is necessary at
delivery time in order to handle homonymic addresses correctly in cases where
the pattern of redirection changes between delivery attempts (so the unique
fields change). Non-homonymic previous delivery is detected earlier, at routing
time (which saves unnecessary routing).

Arguments:
  addr      the address item
  testing   TRUE if testing wanted only, without side effects

Returns:    TRUE if previously delivered by the transport
*/

static BOOL
previously_transported(address_item *addr, BOOL testing)
{
(void)string_format(big_buffer, big_buffer_size, "%s/%s",
  addr->unique + (testflag(addr, af_homonym)? 3:0), addr->transport->name);

if (tree_search(tree_nonrecipients, big_buffer) != 0)
  {
  DEBUG(D_deliver|D_route|D_transport)
    debug_printf("%s was previously delivered (%s transport): discarded\n",
    addr->address, addr->transport->name);
  if (!testing) child_done(addr, tod_stamp(tod_log));
  return TRUE;
  }

return FALSE;
}



/******************************************************
*      Check for a given header in a header string    *
******************************************************/

/* This function is used when generating quota warnings. The configuration may
specify any header lines it likes in quota_warn_message. If certain of them are
missing, defaults are inserted, so we need to be able to test for the presence
of a given header.

Arguments:
  hdr         the required header name
  hstring     the header string

Returns:      TRUE  the header is in the string
              FALSE the header is not in the string
*/

static BOOL
contains_header(uschar *hdr, uschar *hstring)
{
int len = Ustrlen(hdr);
uschar *p = hstring;
while (*p != 0)
  {
  if (strncmpic(p, hdr, len) == 0)
    {
    p += len;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == ':') return TRUE;
    }
  while (*p != 0 && *p != '\n') p++;
  if (*p == '\n') p++;
  }
return FALSE;
}




/*************************************************
*           Perform a local delivery             *
*************************************************/

/* Each local delivery is performed in a separate process which sets its
uid and gid as specified. This is a safer way than simply changing and
restoring using seteuid(); there is a body of opinion that seteuid() cannot be
used safely. From release 4, Exim no longer makes any use of it. Besides, not
all systems have seteuid().

If the uid/gid are specified in the transport_instance, they are used; the
transport initialization must ensure that either both or neither are set.
Otherwise, the values associated with the address are used. If neither are set,
it is a configuration error.

The transport or the address may specify a home directory (transport over-
rides), and if they do, this is set as $home. If neither have set a working
directory, this value is used for that as well. Otherwise $home is left unset
and the cwd is set to "/" - a directory that should be accessible to all users.

Using a separate process makes it more complicated to get error information
back. We use a pipe to pass the return code and also an error code and error
text string back to the parent process.

Arguments:
  addr       points to an address block for this delivery; for "normal" local
             deliveries this is the only address to be delivered, but for
             pseudo-remote deliveries (e.g. by batch SMTP to a file or pipe)
             a number of addresses can be handled simultaneously, and in this
             case addr will point to a chain of addresses with the same
             characteristics.

  shadowing  TRUE if running a shadow transport; this causes output from pipes
             to be ignored.

Returns:     nothing
*/

static void
deliver_local(address_item *addr, BOOL shadowing)
{
BOOL use_initgroups;
uid_t uid;
gid_t gid;
int status, len, rc;
int pfd[2];
pid_t pid;
uschar *working_directory;
address_item *addr2;
transport_instance *tp = addr->transport;

/* Set up the return path from the errors or sender address. If the transport
has its own return path setting, expand it and replace the existing value. */

if(addr->prop.errors_address != NULL)
  return_path = addr->prop.errors_address;
#ifdef EXPERIMENTAL_SRS
else if(addr->prop.srs_sender != NULL)
  return_path = addr->prop.srs_sender;
#endif
else
  return_path = sender_address;

if (tp->return_path != NULL)
  {
  uschar *new_return_path = expand_string(tp->return_path);
  if (new_return_path == NULL)
    {
    if (!expand_string_forcedfail)
      {
      common_error(TRUE, addr, ERRNO_EXPANDFAIL,
        US"Failed to expand return path \"%s\" in %s transport: %s",
        tp->return_path, tp->name, expand_string_message);
      return;
      }
    }
  else return_path = new_return_path;
  }

/* For local deliveries, one at a time, the value used for logging can just be
set directly, once and for all. */

used_return_path = return_path;

/* Sort out the uid, gid, and initgroups flag. If an error occurs, the message
gets put into the address(es), and the expansions are unset, so we can just
return. */

if (!findugid(addr, tp, &uid, &gid, &use_initgroups)) return;

/* See if either the transport or the address specifies a home directory. A
home directory set in the address may already be expanded; a flag is set to
indicate that. In other cases we must expand it. */

if ((deliver_home = tp->home_dir) != NULL ||       /* Set in transport, or */
     ((deliver_home = addr->home_dir) != NULL &&   /* Set in address and */
       !testflag(addr, af_home_expanded)))         /*   not expanded */
  {
  uschar *rawhome = deliver_home;
  deliver_home = NULL;                      /* in case it contains $home */
  deliver_home = expand_string(rawhome);
  if (deliver_home == NULL)
    {
    common_error(TRUE, addr, ERRNO_EXPANDFAIL, US"home directory \"%s\" failed "
      "to expand for %s transport: %s", rawhome, tp->name,
      expand_string_message);
    return;
    }
  if (*deliver_home != '/')
    {
    common_error(TRUE, addr, ERRNO_NOTABSOLUTE, US"home directory path \"%s\" "
      "is not absolute for %s transport", deliver_home, tp->name);
    return;
    }
  }

/* See if either the transport or the address specifies a current directory,
and if so, expand it. If nothing is set, use the home directory, unless it is
also unset in which case use "/", which is assumed to be a directory to which
all users have access. It is necessary to be in a visible directory for some
operating systems when running pipes, as some commands (e.g. "rm" under Solaris
2.5) require this. */

working_directory = (tp->current_dir != NULL)?
  tp->current_dir : addr->current_dir;

if (working_directory != NULL)
  {
  uschar *raw = working_directory;
  working_directory = expand_string(raw);
  if (working_directory == NULL)
    {
    common_error(TRUE, addr, ERRNO_EXPANDFAIL, US"current directory \"%s\" "
      "failed to expand for %s transport: %s", raw, tp->name,
      expand_string_message);
    return;
    }
  if (*working_directory != '/')
    {
    common_error(TRUE, addr, ERRNO_NOTABSOLUTE, US"current directory path "
      "\"%s\" is not absolute for %s transport", working_directory, tp->name);
    return;
    }
  }
else working_directory = (deliver_home == NULL)? US"/" : deliver_home;

/* If one of the return_output flags is set on the transport, create and open a
file in the message log directory for the transport to write its output onto.
This is mainly used by pipe transports. The file needs to be unique to the
address. This feature is not available for shadow transports. */

if (!shadowing && (tp->return_output || tp->return_fail_output ||
    tp->log_output || tp->log_fail_output))
  {
  uschar *error;
  addr->return_filename =
    string_sprintf("%s/msglog/%s/%s-%d-%d", spool_directory, message_subdir,
      message_id, getpid(), return_count++);
  addr->return_file = open_msglog_file(addr->return_filename, 0400, &error);
  if (addr->return_file < 0)
    {
    common_error(TRUE, addr, errno, US"Unable to %s file for %s transport "
      "to return message: %s", error, tp->name, strerror(errno));
    return;
    }
  }

/* Create the pipe for inter-process communication. */

if (pipe(pfd) != 0)
  {
  common_error(TRUE, addr, ERRNO_PIPEFAIL, US"Creation of pipe failed: %s",
    strerror(errno));
  return;
  }

/* Now fork the process to do the real work in the subprocess, but first
ensure that all cached resources are freed so that the subprocess starts with
a clean slate and doesn't interfere with the parent process. */

search_tidyup();

if ((pid = fork()) == 0)
  {
  BOOL replicate = TRUE;

  /* Prevent core dumps, as we don't want them in users' home directories.
  HP-UX doesn't have RLIMIT_CORE; I don't know how to do this in that
  system. Some experimental/developing systems (e.g. GNU/Hurd) may define
  RLIMIT_CORE but not support it in setrlimit(). For such systems, do not
  complain if the error is "not supported".

  There are two scenarios where changing the max limit has an effect.  In one,
  the user is using a .forward and invoking a command of their choice via pipe;
  for these, we do need the max limit to be 0 unless the admin chooses to
  permit an increased limit.  In the other, the command is invoked directly by
  the transport and is under administrator control, thus being able to raise
  the limit aids in debugging.  So there's no general always-right answer.

  Thus we inhibit core-dumps completely but let individual transports, while
  still root, re-raise the limits back up to aid debugging.  We make the
  default be no core-dumps -- few enough people can use core dumps in
  diagnosis that it's reasonable to make them something that has to be explicitly requested.
  */

#ifdef RLIMIT_CORE
  struct rlimit rl;
  rl.rlim_cur = 0;
  rl.rlim_max = 0;
  if (setrlimit(RLIMIT_CORE, &rl) < 0)
    {
# ifdef SETRLIMIT_NOT_SUPPORTED
    if (errno != ENOSYS && errno != ENOTSUP)
# endif
      log_write(0, LOG_MAIN|LOG_PANIC, "setrlimit(RLIMIT_CORE) failed: %s",
        strerror(errno));
    }
#endif

  /* Reset the random number generator, so different processes don't all
  have the same sequence. */

  random_seed = 0;

  /* If the transport has a setup entry, call this first, while still
  privileged. (Appendfile uses this to expand quota, for example, while
  able to read private files.) */

  if (addr->transport->setup != NULL)
    {
    switch((addr->transport->setup)(addr->transport, addr, NULL, uid, gid,
           &(addr->message)))
      {
      case DEFER:
      addr->transport_return = DEFER;
      goto PASS_BACK;

      case FAIL:
      addr->transport_return = PANIC;
      goto PASS_BACK;
      }
    }

  /* Ignore SIGINT and SIGTERM during delivery. Also ignore SIGUSR1, as
  when the process becomes unprivileged, it won't be able to write to the
  process log. SIGHUP is ignored throughout exim, except when it is being
  run as a daemon. */

  signal(SIGINT, SIG_IGN);
  signal(SIGTERM, SIG_IGN);
  signal(SIGUSR1, SIG_IGN);

  /* Close the unwanted half of the pipe, and set close-on-exec for the other
  half - for transports that exec things (e.g. pipe). Then set the required
  gid/uid. */

  (void)close(pfd[pipe_read]);
  (void)fcntl(pfd[pipe_write], F_SETFD, fcntl(pfd[pipe_write], F_GETFD) |
    FD_CLOEXEC);
  exim_setugid(uid, gid, use_initgroups,
    string_sprintf("local delivery to %s <%s> transport=%s", addr->local_part,
      addr->address, addr->transport->name));

  DEBUG(D_deliver)
    {
    address_item *batched;
    debug_printf("  home=%s current=%s\n", deliver_home, working_directory);
    for (batched = addr->next; batched != NULL; batched = batched->next)
      debug_printf("additional batched address: %s\n", batched->address);
    }

  /* Set an appropriate working directory. */

  if (Uchdir(working_directory) < 0)
    {
    addr->transport_return = DEFER;
    addr->basic_errno = errno;
    addr->message = string_sprintf("failed to chdir to %s", working_directory);
    }

  /* If successful, call the transport */

  else
    {
    BOOL ok = TRUE;
    set_process_info("delivering %s to %s using %s", message_id,
     addr->local_part, addr->transport->name);

    /* Setting this global in the subprocess means we need never clear it */
    transport_name = addr->transport->name;

    /* If a transport filter has been specified, set up its argument list.
    Any errors will get put into the address, and FALSE yielded. */

    if (addr->transport->filter_command != NULL)
      {
      ok = transport_set_up_command(&transport_filter_argv,
        addr->transport->filter_command,
        TRUE, PANIC, addr, US"transport filter", NULL);
      transport_filter_timeout = addr->transport->filter_timeout;
      }
    else transport_filter_argv = NULL;

    if (ok)
      {
      debug_print_string(addr->transport->debug_string);
      replicate = !(addr->transport->info->code)(addr->transport, addr);
      }
    }

  /* Pass the results back down the pipe. If necessary, first replicate the
  status in the top address to the others in the batch. The label is the
  subject of a goto when a call to the transport's setup function fails. We
  pass the pointer to the transport back in case it got changed as a result of
  file_format in appendfile. */

  PASS_BACK:

  if (replicate) replicate_status(addr);
  for (addr2 = addr; addr2 != NULL; addr2 = addr2->next)
    {
    int i;
    int local_part_length = Ustrlen(addr2->local_part);
    uschar *s;
    int ret;

    if(  (ret = write(pfd[pipe_write], (void *)&(addr2->transport_return), sizeof(int))) != sizeof(int)
      || (ret = write(pfd[pipe_write], (void *)&transport_count, sizeof(transport_count))) != sizeof(transport_count)
      || (ret = write(pfd[pipe_write], (void *)&(addr2->flags), sizeof(addr2->flags))) != sizeof(addr2->flags)
      || (ret = write(pfd[pipe_write], (void *)&(addr2->basic_errno), sizeof(int))) != sizeof(int)
      || (ret = write(pfd[pipe_write], (void *)&(addr2->more_errno), sizeof(int))) != sizeof(int)
      || (ret = write(pfd[pipe_write], (void *)&(addr2->special_action), sizeof(int))) != sizeof(int)
      || (ret = write(pfd[pipe_write], (void *)&(addr2->transport),
        sizeof(transport_instance *))) != sizeof(transport_instance *)

    /* For a file delivery, pass back the local part, in case the original
    was only part of the final delivery path. This gives more complete
    logging. */

      || (testflag(addr2, af_file)
          && (  (ret = write(pfd[pipe_write], (void *)&local_part_length, sizeof(int))) != sizeof(int)
             || (ret = write(pfd[pipe_write], addr2->local_part, local_part_length)) != local_part_length
	     )
	 )
      )
      log_write(0, LOG_MAIN|LOG_PANIC, "Failed writing transport results to pipe: %s\n",
	ret == -1 ? strerror(errno) : "short write");

    /* Now any messages */

    for (i = 0, s = addr2->message; i < 2; i++, s = addr2->user_message)
      {
      int message_length = (s == NULL)? 0 : Ustrlen(s) + 1;
      if(  (ret = write(pfd[pipe_write], (void *)&message_length, sizeof(int))) != sizeof(int)
        || (message_length > 0  && (ret = write(pfd[pipe_write], s, message_length)) != message_length)
	)
        log_write(0, LOG_MAIN|LOG_PANIC, "Failed writing transport results to pipe: %s\n",
	  ret == -1 ? strerror(errno) : "short write");
      }
    }

  /* OK, this process is now done. Free any cached resources that it opened,
  and close the pipe we were writing down before exiting. */

  (void)close(pfd[pipe_write]);
  search_tidyup();
  exit(EXIT_SUCCESS);
  }

/* Back in the main process: panic if the fork did not succeed. This seems
better than returning an error - if forking is failing it is probably best
not to try other deliveries for this message. */

if (pid < 0)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "Fork failed for local delivery to %s",
    addr->address);

/* Read the pipe to get the delivery status codes and error messages. Our copy
of the writing end must be closed first, as otherwise read() won't return zero
on an empty pipe. We check that a status exists for each address before
overwriting the address structure. If data is missing, the default DEFER status
will remain. Afterwards, close the reading end. */

(void)close(pfd[pipe_write]);

for (addr2 = addr; addr2 != NULL; addr2 = addr2->next)
  {
  len = read(pfd[pipe_read], (void *)&status, sizeof(int));
  if (len > 0)
    {
    int i;
    uschar **sptr;

    addr2->transport_return = status;
    len = read(pfd[pipe_read], (void *)&transport_count,
      sizeof(transport_count));
    len = read(pfd[pipe_read], (void *)&(addr2->flags), sizeof(addr2->flags));
    len = read(pfd[pipe_read], (void *)&(addr2->basic_errno), sizeof(int));
    len = read(pfd[pipe_read], (void *)&(addr2->more_errno), sizeof(int));
    len = read(pfd[pipe_read], (void *)&(addr2->special_action), sizeof(int));
    len = read(pfd[pipe_read], (void *)&(addr2->transport),
      sizeof(transport_instance *));

    if (testflag(addr2, af_file))
      {
      int local_part_length;
      len = read(pfd[pipe_read], (void *)&local_part_length, sizeof(int));
      len = read(pfd[pipe_read], (void *)big_buffer, local_part_length);
      big_buffer[local_part_length] = 0;
      addr2->local_part = string_copy(big_buffer);
      }

    for (i = 0, sptr = &(addr2->message); i < 2;
         i++, sptr = &(addr2->user_message))
      {
      int message_length;
      len = read(pfd[pipe_read], (void *)&message_length, sizeof(int));
      if (message_length > 0)
        {
        len = read(pfd[pipe_read], (void *)big_buffer, message_length);
        if (len > 0) *sptr = string_copy(big_buffer);
        }
      }
    }

  else
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "failed to read delivery status for %s "
      "from delivery subprocess", addr2->unique);
    break;
    }
  }

(void)close(pfd[pipe_read]);

/* Unless shadowing, write all successful addresses immediately to the journal
file, to ensure they are recorded asap. For homonymic addresses, use the base
address plus the transport name. Failure to write the journal is panic-worthy,
but don't stop, as it may prove possible subsequently to update the spool file
in order to record the delivery. */

if (!shadowing)
  {
  for (addr2 = addr; addr2 != NULL; addr2 = addr2->next)
    {
    if (addr2->transport_return != OK) continue;

    if (testflag(addr2, af_homonym))
      sprintf(CS big_buffer, "%.500s/%s\n", addr2->unique + 3, tp->name);
    else
      sprintf(CS big_buffer, "%.500s\n", addr2->unique);

    /* In the test harness, wait just a bit to let the subprocess finish off
    any debug output etc first. */

    if (running_in_test_harness) millisleep(300);

    DEBUG(D_deliver) debug_printf("journalling %s", big_buffer);
    len = Ustrlen(big_buffer);
    if (write(journal_fd, big_buffer, len) != len)
      log_write(0, LOG_MAIN|LOG_PANIC, "failed to update journal for %s: %s",
        big_buffer, strerror(errno));
    }

  /* Ensure the journal file is pushed out to disk. */

  if (EXIMfsync(journal_fd) < 0)
    log_write(0, LOG_MAIN|LOG_PANIC, "failed to fsync journal: %s",
      strerror(errno));
  }

/* Wait for the process to finish. If it terminates with a non-zero code,
freeze the message (except for SIGTERM, SIGKILL and SIGQUIT), but leave the
status values of all the addresses as they are. Take care to handle the case
when the subprocess doesn't seem to exist. This has been seen on one system
when Exim was called from an MUA that set SIGCHLD to SIG_IGN. When that
happens, wait() doesn't recognize the termination of child processes. Exim now
resets SIGCHLD to SIG_DFL, but this code should still be robust. */

while ((rc = wait(&status)) != pid)
  {
  if (rc < 0 && errno == ECHILD)      /* Process has vanished */
    {
    log_write(0, LOG_MAIN, "%s transport process vanished unexpectedly",
      addr->transport->driver_name);
    status = 0;
    break;
    }
  }

if ((status & 0xffff) != 0)
  {
  int msb = (status >> 8) & 255;
  int lsb = status & 255;
  int code = (msb == 0)? (lsb & 0x7f) : msb;
  if (msb != 0 || (code != SIGTERM && code != SIGKILL && code != SIGQUIT))
    addr->special_action = SPECIAL_FREEZE;
  log_write(0, LOG_MAIN|LOG_PANIC, "%s transport process returned non-zero "
    "status 0x%04x: %s %d",
    addr->transport->driver_name,
    status,
    (msb == 0)? "terminated by signal" : "exit code",
    code);
  }

/* If SPECIAL_WARN is set in the top address, send a warning message. */

if (addr->special_action == SPECIAL_WARN &&
    addr->transport->warn_message != NULL)
  {
  int fd;
  uschar *warn_message;

  DEBUG(D_deliver) debug_printf("Warning message requested by transport\n");

  warn_message = expand_string(addr->transport->warn_message);
  if (warn_message == NULL)
    log_write(0, LOG_MAIN|LOG_PANIC, "Failed to expand \"%s\" (warning "
      "message for %s transport): %s", addr->transport->warn_message,
      addr->transport->name, expand_string_message);
  else
    {
    pid_t pid = child_open_exim(&fd);
    if (pid > 0)
      {
      FILE *f = fdopen(fd, "wb");
      if (errors_reply_to != NULL &&
          !contains_header(US"Reply-To", warn_message))
        fprintf(f, "Reply-To: %s\n", errors_reply_to);
      fprintf(f, "Auto-Submitted: auto-replied\n");
      if (!contains_header(US"From", warn_message)) moan_write_from(f);
      fprintf(f, "%s", CS warn_message);

      /* Close and wait for child process to complete, without a timeout. */

      (void)fclose(f);
      (void)child_close(pid, 0);
      }
    }

  addr->special_action = SPECIAL_NONE;
  }
}



/*************************************************
*              Do local deliveries               *
*************************************************/

/* This function processes the list of addresses in addr_local. True local
deliveries are always done one address at a time. However, local deliveries can
be batched up in some cases. Typically this is when writing batched SMTP output
files for use by some external transport mechanism, or when running local
deliveries over LMTP.

Arguments:   None
Returns:     Nothing
*/

static void
do_local_deliveries(void)
{
open_db dbblock;
open_db *dbm_file = NULL;
time_t now = time(NULL);

/* Loop until we have exhausted the supply of local deliveries */

while (addr_local != NULL)
  {
  time_t delivery_start;
  int deliver_time;
  address_item *addr2, *addr3, *nextaddr;
  int logflags = LOG_MAIN;
  int logchar = dont_deliver? '*' : '=';
  transport_instance *tp;

  /* Pick the first undelivered address off the chain */

  address_item *addr = addr_local;
  addr_local = addr->next;
  addr->next = NULL;

  DEBUG(D_deliver|D_transport)
    debug_printf("--------> %s <--------\n", addr->address);

  /* An internal disaster if there is no transport. Should not occur! */

  if ((tp = addr->transport) == NULL)
    {
    logflags |= LOG_PANIC;
    disable_logging = FALSE;  /* Jic */
    addr->message =
      (addr->router != NULL)?
        string_sprintf("No transport set by %s router", addr->router->name)
        :
        string_sprintf("No transport set by system filter");
    post_process_one(addr, DEFER, logflags, DTYPE_TRANSPORT, 0);
    continue;
    }

  /* Check that this base address hasn't previously been delivered to this
  transport. The check is necessary at this point to handle homonymic addresses
  correctly in cases where the pattern of redirection changes between delivery
  attempts. Non-homonymic previous delivery is detected earlier, at routing
  time. */

  if (previously_transported(addr, FALSE)) continue;

  /* There are weird cases where logging is disabled */

  disable_logging = tp->disable_logging;

  /* Check for batched addresses and possible amalgamation. Skip all the work
  if either batch_max <= 1 or there aren't any other addresses for local
  delivery. */

  if (tp->batch_max > 1 && addr_local != NULL)
    {
    int batch_count = 1;
    BOOL uses_dom = readconf_depends((driver_instance *)tp, US"domain");
    BOOL uses_lp = (testflag(addr, af_pfr) &&
      (testflag(addr, af_file) || addr->local_part[0] == '|')) ||
      readconf_depends((driver_instance *)tp, US"local_part");
    uschar *batch_id = NULL;
    address_item **anchor = &addr_local;
    address_item *last = addr;
    address_item *next;

    /* Expand the batch_id string for comparison with other addresses.
    Expansion failure suppresses batching. */

    if (tp->batch_id != NULL)
      {
      deliver_set_expansions(addr);
      batch_id = expand_string(tp->batch_id);
      deliver_set_expansions(NULL);
      if (batch_id == NULL)
        {
        log_write(0, LOG_MAIN|LOG_PANIC, "Failed to expand batch_id option "
          "in %s transport (%s): %s", tp->name, addr->address,
          expand_string_message);
        batch_count = tp->batch_max;
        }
      }

    /* Until we reach the batch_max limit, pick off addresses which have the
    same characteristics. These are:

      same transport
      not previously delivered (see comment about 50 lines above)
      same local part if the transport's configuration contains $local_part
        or if this is a file or pipe delivery from a redirection
      same domain if the transport's configuration contains $domain
      same errors address
      same additional headers
      same headers to be removed
      same uid/gid for running the transport
      same first host if a host list is set
    */

    while ((next = *anchor) != NULL && batch_count < tp->batch_max)
      {
      BOOL ok =
        tp == next->transport &&
        !previously_transported(next, TRUE) &&
        (addr->flags & (af_pfr|af_file)) == (next->flags & (af_pfr|af_file)) &&
        (!uses_lp  || Ustrcmp(next->local_part, addr->local_part) == 0) &&
        (!uses_dom || Ustrcmp(next->domain, addr->domain) == 0) &&
        same_strings(next->prop.errors_address, addr->prop.errors_address) &&
        same_headers(next->prop.extra_headers, addr->prop.extra_headers) &&
        same_strings(next->prop.remove_headers, addr->prop.remove_headers) &&
        same_ugid(tp, addr, next) &&
        ((addr->host_list == NULL && next->host_list == NULL) ||
         (addr->host_list != NULL && next->host_list != NULL &&
          Ustrcmp(addr->host_list->name, next->host_list->name) == 0));

      /* If the transport has a batch_id setting, batch_id will be non-NULL
      from the expansion outside the loop. Expand for this address and compare.
      Expansion failure makes this address ineligible for batching. */

      if (ok && batch_id != NULL)
        {
        uschar *bid;
        address_item *save_nextnext = next->next;
        next->next = NULL;            /* Expansion for a single address */
        deliver_set_expansions(next);
        next->next = save_nextnext;
        bid = expand_string(tp->batch_id);
        deliver_set_expansions(NULL);
        if (bid == NULL)
          {
          log_write(0, LOG_MAIN|LOG_PANIC, "Failed to expand batch_id option "
            "in %s transport (%s): %s", tp->name, next->address,
            expand_string_message);
          ok = FALSE;
          }
        else ok = (Ustrcmp(batch_id, bid) == 0);
        }

      /* Take address into batch if OK. */

      if (ok)
        {
        *anchor = next->next;           /* Include the address */
        next->next = NULL;
        last->next = next;
        last = next;
        batch_count++;
        }
      else anchor = &(next->next);      /* Skip the address */
      }
    }

  /* We now have one or more addresses that can be delivered in a batch. Check
  whether the transport is prepared to accept a message of this size. If not,
  fail them all forthwith. If the expansion fails, or does not yield an
  integer, defer delivery. */

  if (tp->message_size_limit != NULL)
    {
    int rc = check_message_size(tp, addr);
    if (rc != OK)
      {
      replicate_status(addr);
      while (addr != NULL)
        {
        addr2 = addr->next;
        post_process_one(addr, rc, logflags, DTYPE_TRANSPORT, 0);
        addr = addr2;
        }
      continue;    /* With next batch of addresses */
      }
    }

  /* If we are not running the queue, or if forcing, all deliveries will be
  attempted. Otherwise, we must respect the retry times for each address. Even
  when not doing this, we need to set up the retry key string, and determine
  whether a retry record exists, because after a successful delivery, a delete
  retry item must be set up. Keep the retry database open only for the duration
  of these checks, rather than for all local deliveries, because some local
  deliveries (e.g. to pipes) can take a substantial time. */

  dbm_file = dbfn_open(US"retry", O_RDONLY, &dbblock, FALSE);
  if (dbm_file == NULL)
    {
    DEBUG(D_deliver|D_retry|D_hints_lookup)
      debug_printf("no retry data available\n");
    }

  addr2 = addr;
  addr3 = NULL;
  while (addr2 != NULL)
    {
    BOOL ok = TRUE;   /* to deliver this address */
    uschar *retry_key;

    /* Set up the retry key to include the domain or not, and change its
    leading character from "R" to "T". Must make a copy before doing this,
    because the old key may be pointed to from a "delete" retry item after
    a routing delay. */

    retry_key = string_copy(
      (tp->retry_use_local_part)? addr2->address_retry_key :
        addr2->domain_retry_key);
    *retry_key = 'T';

    /* Inspect the retry data. If there is no hints file, delivery happens. */

    if (dbm_file != NULL)
      {
      dbdata_retry *retry_record = dbfn_read(dbm_file, retry_key);

      /* If there is no retry record, delivery happens. If there is,
      remember it exists so it can be deleted after a successful delivery. */

      if (retry_record != NULL)
        {
        setflag(addr2, af_lt_retry_exists);

        /* A retry record exists for this address. If queue running and not
        forcing, inspect its contents. If the record is too old, or if its
        retry time has come, or if it has passed its cutoff time, delivery
        will go ahead. */

        DEBUG(D_retry)
          {
          debug_printf("retry record exists: age=%s ",
            readconf_printtime(now - retry_record->time_stamp));
          debug_printf("(max %s)\n", readconf_printtime(retry_data_expire));
          debug_printf("  time to retry = %s expired = %d\n",
            readconf_printtime(retry_record->next_try - now),
            retry_record->expired);
          }

        if (queue_running && !deliver_force)
          {
          ok = (now - retry_record->time_stamp > retry_data_expire) ||
               (now >= retry_record->next_try) ||
               retry_record->expired;

          /* If we haven't reached the retry time, there is one more check
          to do, which is for the ultimate address timeout. */

          if (!ok)
            ok = retry_ultimate_address_timeout(retry_key, addr2->domain,
                retry_record, now);
          }
        }
      else DEBUG(D_retry) debug_printf("no retry record exists\n");
      }

    /* This address is to be delivered. Leave it on the chain. */

    if (ok)
      {
      addr3 = addr2;
      addr2 = addr2->next;
      }

    /* This address is to be deferred. Take it out of the chain, and
    post-process it as complete. Must take it out of the chain first,
    because post processing puts it on another chain. */

    else
      {
      address_item *this = addr2;
      this->message = US"Retry time not yet reached";
      this->basic_errno = ERRNO_LRETRY;
      if (addr3 == NULL) addr2 = addr = addr2->next;
        else addr2 = addr3->next = addr2->next;
      post_process_one(this, DEFER, logflags, DTYPE_TRANSPORT, 0);
      }
    }

  if (dbm_file != NULL) dbfn_close(dbm_file);

  /* If there are no addresses left on the chain, they all deferred. Loop
  for the next set of addresses. */

  if (addr == NULL) continue;

  /* So, finally, we do have some addresses that can be passed to the
  transport. Before doing so, set up variables that are relevant to a
  single delivery. */

  deliver_set_expansions(addr);
  delivery_start = time(NULL);
  deliver_local(addr, FALSE);
  deliver_time = (int)(time(NULL) - delivery_start);

  /* If a shadow transport (which must perforce be another local transport), is
  defined, and its condition is met, we must pass the message to the shadow
  too, but only those addresses that succeeded. We do this by making a new
  chain of addresses - also to keep the original chain uncontaminated. We must
  use a chain rather than doing it one by one, because the shadow transport may
  batch.

  NOTE: if the condition fails because of a lookup defer, there is nothing we
  can do! */

  if (tp->shadow != NULL &&
      (tp->shadow_condition == NULL ||
      expand_check_condition(tp->shadow_condition, tp->name, US"transport")))
    {
    transport_instance *stp;
    address_item *shadow_addr = NULL;
    address_item **last = &shadow_addr;

    for (stp = transports; stp != NULL; stp = stp->next)
      if (Ustrcmp(stp->name, tp->shadow) == 0) break;

    if (stp == NULL)
      log_write(0, LOG_MAIN|LOG_PANIC, "shadow transport \"%s\" not found ",
        tp->shadow);

    /* Pick off the addresses that have succeeded, and make clones. Put into
    the shadow_message field a pointer to the shadow_message field of the real
    address. */

    else for (addr2 = addr; addr2 != NULL; addr2 = addr2->next)
      {
      if (addr2->transport_return != OK) continue;
      addr3 = store_get(sizeof(address_item));
      *addr3 = *addr2;
      addr3->next = NULL;
      addr3->shadow_message = (uschar *)(&(addr2->shadow_message));
      addr3->transport = stp;
      addr3->transport_return = DEFER;
      addr3->return_filename = NULL;
      addr3->return_file = -1;
      *last = addr3;
      last = &(addr3->next);
      }

    /* If we found any addresses to shadow, run the delivery, and stick any
    message back into the shadow_message field in the original. */

    if (shadow_addr != NULL)
      {
      int save_count = transport_count;

      DEBUG(D_deliver|D_transport)
        debug_printf(">>>>>>>>>>>>>>>> Shadow delivery >>>>>>>>>>>>>>>>\n");
      deliver_local(shadow_addr, TRUE);

      for(; shadow_addr != NULL; shadow_addr = shadow_addr->next)
        {
        int sresult = shadow_addr->transport_return;
        *((uschar **)(shadow_addr->shadow_message)) = (sresult == OK)?
          string_sprintf(" ST=%s", stp->name) :
          string_sprintf(" ST=%s (%s%s%s)", stp->name,
            (shadow_addr->basic_errno <= 0)?
              US"" : US strerror(shadow_addr->basic_errno),
            (shadow_addr->basic_errno <= 0 || shadow_addr->message == NULL)?
              US"" : US": ",
            (shadow_addr->message != NULL)? shadow_addr->message :
              (shadow_addr->basic_errno <= 0)? US"unknown error" : US"");

        DEBUG(D_deliver|D_transport)
          debug_printf("%s shadow transport returned %s for %s\n",
            stp->name,
            (sresult == OK)?    "OK" :
            (sresult == DEFER)? "DEFER" :
            (sresult == FAIL)?  "FAIL" :
            (sresult == PANIC)? "PANIC" : "?",
            shadow_addr->address);
        }

      DEBUG(D_deliver|D_transport)
        debug_printf(">>>>>>>>>>>>>>>> End shadow delivery >>>>>>>>>>>>>>>>\n");

      transport_count = save_count;   /* Restore original transport count */
      }
    }

  /* Cancel the expansions that were set up for the delivery. */

  deliver_set_expansions(NULL);

  /* Now we can process the results of the real transport. We must take each
  address off the chain first, because post_process_one() puts it on another
  chain. */

  for (addr2 = addr; addr2 != NULL; addr2 = nextaddr)
    {
    int result = addr2->transport_return;
    nextaddr = addr2->next;

    DEBUG(D_deliver|D_transport)
      debug_printf("%s transport returned %s for %s\n",
        tp->name,
        (result == OK)?    "OK" :
        (result == DEFER)? "DEFER" :
        (result == FAIL)?  "FAIL" :
        (result == PANIC)? "PANIC" : "?",
        addr2->address);

    /* If there is a retry_record, or if delivery is deferred, build a retry
    item for setting a new retry time or deleting the old retry record from
    the database. These items are handled all together after all addresses
    have been handled (so the database is open just for a short time for
    updating). */

    if (result == DEFER || testflag(addr2, af_lt_retry_exists))
      {
      int flags = (result == DEFER)? 0 : rf_delete;
      uschar *retry_key = string_copy((tp->retry_use_local_part)?
        addr2->address_retry_key : addr2->domain_retry_key);
      *retry_key = 'T';
      retry_add_item(addr2, retry_key, flags);
      }

    /* Done with this address */

    if (result == OK) addr2->more_errno = deliver_time;
    post_process_one(addr2, result, logflags, DTYPE_TRANSPORT, logchar);

    /* If a pipe delivery generated text to be sent back, the result may be
    changed to FAIL, and we must copy this for subsequent addresses in the
    batch. */

    if (addr2->transport_return != result)
      {
      for (addr3 = nextaddr; addr3 != NULL; addr3 = addr3->next)
        {
        addr3->transport_return = addr2->transport_return;
        addr3->basic_errno = addr2->basic_errno;
        addr3->message = addr2->message;
        }
      result = addr2->transport_return;
      }

    /* Whether or not the result was changed to FAIL, we need to copy the
    return_file value from the first address into all the addresses of the
    batch, so they are all listed in the error message. */

    addr2->return_file = addr->return_file;

    /* Change log character for recording successful deliveries. */

    if (result == OK) logchar = '-';
    }
  }        /* Loop back for next batch of addresses */
}




/*************************************************
*           Sort remote deliveries               *
*************************************************/

/* This function is called if remote_sort_domains is set. It arranges that the
chain of addresses for remote deliveries is ordered according to the strings
specified. Try to make this shuffling reasonably efficient by handling
sequences of addresses rather than just single ones.

Arguments:  None
Returns:    Nothing
*/

static void
sort_remote_deliveries(void)
{
int sep = 0;
address_item **aptr = &addr_remote;
const uschar *listptr = remote_sort_domains;
uschar *pattern;
uschar patbuf[256];

while (*aptr != NULL &&
       (pattern = string_nextinlist(&listptr, &sep, patbuf, sizeof(patbuf)))
       != NULL)
  {
  address_item *moved = NULL;
  address_item **bptr = &moved;

  while (*aptr != NULL)
    {
    address_item **next;
    deliver_domain = (*aptr)->domain;   /* set $domain */
    if (match_isinlist(deliver_domain, (const uschar **)&pattern, UCHAR_MAX+1,
          &domainlist_anchor, NULL, MCL_DOMAIN, TRUE, NULL) == OK)
      {
      aptr = &((*aptr)->next);
      continue;
      }

    next = &((*aptr)->next);
    while (*next != NULL &&
           (deliver_domain = (*next)->domain,  /* Set $domain */
            match_isinlist(deliver_domain, (const uschar **)&pattern, UCHAR_MAX+1,
              &domainlist_anchor, NULL, MCL_DOMAIN, TRUE, NULL)) != OK)
      next = &((*next)->next);

    /* If the batch of non-matchers is at the end, add on any that were
    extracted further up the chain, and end this iteration. Otherwise,
    extract them from the chain and hang on the moved chain. */

    if (*next == NULL)
      {
      *next = moved;
      break;
      }

    *bptr = *aptr;
    *aptr = *next;
    *next = NULL;
    bptr = next;
    aptr = &((*aptr)->next);
    }

  /* If the loop ended because the final address matched, *aptr will
  be NULL. Add on to the end any extracted non-matching addresses. If
  *aptr is not NULL, the loop ended via "break" when *next is null, that
  is, there was a string of non-matching addresses at the end. In this
  case the extracted addresses have already been added on the end. */

  if (*aptr == NULL) *aptr = moved;
  }

DEBUG(D_deliver)
  {
  address_item *addr;
  debug_printf("remote addresses after sorting:\n");
  for (addr = addr_remote; addr != NULL; addr = addr->next)
    debug_printf("  %s\n", addr->address);
  }
}



/*************************************************
*  Read from pipe for remote delivery subprocess *
*************************************************/

/* This function is called when the subprocess is complete, but can also be
called before it is complete, in order to empty a pipe that is full (to prevent
deadlock). It must therefore keep track of its progress in the parlist data
block.

We read the pipe to get the delivery status codes and a possible error message
for each address, optionally preceded by unusability data for the hosts and
also by optional retry data.

Read in large chunks into the big buffer and then scan through, interpreting
the data therein. In most cases, only a single read will be necessary. No
individual item will ever be anywhere near 2500 bytes in length, so by ensuring
that we read the next chunk when there is less than 2500 bytes left in the
non-final chunk, we can assume each item is complete in the buffer before
handling it. Each item is written using a single write(), which is atomic for
small items (less than PIPE_BUF, which seems to be at least 512 in any Unix and
often bigger) so even if we are reading while the subprocess is still going, we
should never have only a partial item in the buffer.

Argument:
  poffset     the offset of the parlist item
  eop         TRUE if the process has completed

Returns:      TRUE if the terminating 'Z' item has been read,
              or there has been a disaster (i.e. no more data needed);
              FALSE otherwise
*/

static BOOL
par_read_pipe(int poffset, BOOL eop)
{
host_item *h;
pardata *p = parlist + poffset;
address_item *addrlist = p->addrlist;
address_item *addr = p->addr;
pid_t pid = p->pid;
int fd = p->fd;
uschar *endptr = big_buffer;
uschar *ptr = endptr;
uschar *msg = p->msg;
BOOL done = p->done;
BOOL unfinished = TRUE;
/* minimum size to read is header size including id, subid and length */
int required = PIPE_HEADER_SIZE;

/* Loop through all items, reading from the pipe when necessary. The pipe
is set up to be non-blocking, but there are two different Unix mechanisms in
use. Exim uses O_NONBLOCK if it is defined. This returns 0 for end of file,
and EAGAIN for no more data. If O_NONBLOCK is not defined, Exim uses O_NDELAY,
which returns 0 for both end of file and no more data. We distinguish the
two cases by taking 0 as end of file only when we know the process has
completed.

Each separate item is written to the pipe in a single write(), and as they are
all short items, the writes will all be atomic and we should never find
ourselves in the position of having read an incomplete item. "Short" in this
case can mean up to about 1K in the case when there is a long error message
associated with an address. */

DEBUG(D_deliver) debug_printf("reading pipe for subprocess %d (%s)\n",
  (int)p->pid, eop? "ended" : "not ended");

while (!done)
  {
  retry_item *r, **rp;
  int remaining = endptr - ptr;
  uschar header[PIPE_HEADER_SIZE + 1];
  uschar id, subid;
  uschar *endc;

  /* Read (first time) or top up the chars in the buffer if necessary.
  There will be only one read if we get all the available data (i.e. don't
  fill the buffer completely). */

  if (remaining < required && unfinished)
    {
    int len;
    int available = big_buffer_size - remaining;

    if (remaining > 0) memmove(big_buffer, ptr, remaining);

    ptr = big_buffer;
    endptr = big_buffer + remaining;
    len = read(fd, endptr, available);

    DEBUG(D_deliver) debug_printf("read() yielded %d\n", len);

    /* If the result is EAGAIN and the process is not complete, just
    stop reading any more and process what we have already. */

    if (len < 0)
      {
      if (!eop && errno == EAGAIN) len = 0; else
        {
        msg = string_sprintf("failed to read pipe from transport process "
          "%d for transport %s: %s", pid, addr->transport->driver_name,
          strerror(errno));
        break;
        }
      }

    /* If the length is zero (eof or no-more-data), just process what we
    already have. Note that if the process is still running and we have
    read all the data in the pipe (but less that "available") then we
    won't read any more, as "unfinished" will get set FALSE. */

    endptr += len;
    remaining += len;
    unfinished = len == available;
    }

  /* If we are at the end of the available data, exit the loop. */
  if (ptr >= endptr) break;

  /* copy and read header */
  memcpy(header, ptr, PIPE_HEADER_SIZE);
  header[PIPE_HEADER_SIZE] = '\0'; 
  id = header[0];
  subid = header[1];
  required = Ustrtol(header + 2, &endc, 10) + PIPE_HEADER_SIZE;     /* header + data */
  if (*endc)
    {
    msg = string_sprintf("failed to read pipe from transport process "
      "%d for transport %s: error reading size from header", pid, addr->transport->driver_name);
    done = TRUE;
    break;
    }

  DEBUG(D_deliver)
    debug_printf("header read  id:%c,subid:%c,size:%s,required:%d,remaining:%d,unfinished:%d\n", 
                    id, subid, header+2, required, remaining, unfinished);

  /* is there room for the dataset we want to read ? */
  if (required > big_buffer_size - PIPE_HEADER_SIZE)
    {
    msg = string_sprintf("failed to read pipe from transport process "
      "%d for transport %s: big_buffer too small! required size=%d buffer size=%d", pid, addr->transport->driver_name,
      required, big_buffer_size - PIPE_HEADER_SIZE);
    done = TRUE;
    break;
    }

  /* we wrote all datasets with atomic write() calls 
     remaining < required only happens if big_buffer was too small
     to get all available data from pipe. unfinished has to be true 
     as well. */
  if (remaining < required)
    {
    if (unfinished)
      continue;
    msg = string_sprintf("failed to read pipe from transport process "
      "%d for transport %s: required size=%d > remaining size=%d and unfinished=false", 
      pid, addr->transport->driver_name, required, remaining);
    done = TRUE;
    break;
    }

  /* step behind the header */
  ptr += PIPE_HEADER_SIZE;
 
  /* Handle each possible type of item, assuming the complete item is
  available in store. */

  switch (id)
    {
    /* Host items exist only if any hosts were marked unusable. Match
    up by checking the IP address. */

    case 'H':
    for (h = addrlist->host_list; h != NULL; h = h->next)
      {
      if (h->address == NULL || Ustrcmp(h->address, ptr+2) != 0) continue;
      h->status = ptr[0];
      h->why = ptr[1];
      }
    ptr += 2;
    while (*ptr++);
    break;

    /* Retry items are sent in a preceding R item for each address. This is
    kept separate to keep each message short enough to guarantee it won't
    be split in the pipe. Hopefully, in the majority of cases, there won't in
    fact be any retry items at all.

    The complete set of retry items might include an item to delete a
    routing retry if there was a previous routing delay. However, routing
    retries are also used when a remote transport identifies an address error.
    In that case, there may also be an "add" item for the same key. Arrange
    that a "delete" item is dropped in favour of an "add" item. */

    case 'R':
    if (addr == NULL) goto ADDR_MISMATCH;

    DEBUG(D_deliver|D_retry)
      debug_printf("reading retry information for %s from subprocess\n",
        ptr+1);

    /* Cut out any "delete" items on the list. */

    for (rp = &(addr->retries); (r = *rp) != NULL; rp = &(r->next))
      {
      if (Ustrcmp(r->key, ptr+1) == 0)           /* Found item with same key */
        {
        if ((r->flags & rf_delete) == 0) break;  /* It was not "delete" */
        *rp = r->next;                           /* Excise a delete item */
        DEBUG(D_deliver|D_retry)
          debug_printf("  existing delete item dropped\n");
        }
      }

    /* We want to add a delete item only if there is no non-delete item;
    however we still have to step ptr through the data. */

    if (r == NULL || (*ptr & rf_delete) == 0)
      {
      r = store_get(sizeof(retry_item));
      r->next = addr->retries;
      addr->retries = r;
      r->flags = *ptr++;
      r->key = string_copy(ptr);
      while (*ptr++);
      memcpy(&(r->basic_errno), ptr, sizeof(r->basic_errno));
      ptr += sizeof(r->basic_errno);
      memcpy(&(r->more_errno), ptr, sizeof(r->more_errno));
      ptr += sizeof(r->more_errno);
      r->message = (*ptr)? string_copy(ptr) : NULL;
      DEBUG(D_deliver|D_retry)
        debug_printf("  added %s item\n",
          ((r->flags & rf_delete) == 0)? "retry" : "delete");
      }

    else
      {
      DEBUG(D_deliver|D_retry)
        debug_printf("  delete item not added: non-delete item exists\n");
      ptr++;
      while(*ptr++);
      ptr += sizeof(r->basic_errno) + sizeof(r->more_errno);
      }

    while(*ptr++);
    break;

    /* Put the amount of data written into the parlist block */

    case 'S':
    memcpy(&(p->transport_count), ptr, sizeof(transport_count));
    ptr += sizeof(transport_count);
    break;

    /* Address items are in the order of items on the address chain. We
    remember the current address value in case this function is called
    several times to empty the pipe in stages. Information about delivery
    over TLS is sent in a preceding X item for each address. We don't put
    it in with the other info, in order to keep each message short enough to
    guarantee it won't be split in the pipe. */

#ifdef SUPPORT_TLS
    case 'X':
    if (addr == NULL) goto ADDR_MISMATCH;          /* Below, in 'A' handler */
    switch (subid)
      {
      case '1':
      addr->cipher = NULL;
      addr->peerdn = NULL;

      if (*ptr)
	addr->cipher = string_copy(ptr);
      while (*ptr++);
      if (*ptr)
	addr->peerdn = string_copy(ptr);
      break;

      case '2':
      if (*ptr)
	(void) tls_import_cert(ptr, &addr->peercert);
      else
	addr->peercert = NULL;
      break;

      case '3':
      if (*ptr)
	(void) tls_import_cert(ptr, &addr->ourcert);
      else
	addr->ourcert = NULL;
      break;

# ifndef DISABLE_OCSP
      case '4':
      addr->ocsp = OCSP_NOT_REQ;
      if (*ptr)
	addr->ocsp = *ptr - '0';
      break;
# endif
      }
    while (*ptr++);
    break;
#endif	/*SUPPORT_TLS*/

    case 'C':	/* client authenticator information */
    switch (subid)
      {
      case '1':
	addr->authenticator = (*ptr)? string_copy(ptr) : NULL;
	break;
      case '2':
	addr->auth_id = (*ptr)? string_copy(ptr) : NULL;
	break;
      case '3':
	addr->auth_sndr = (*ptr)? string_copy(ptr) : NULL;
	break;
      }
    while (*ptr++);
    break;

#ifndef DISABLE_PRDR
    case 'P':
    addr->flags |= af_prdr_used;
    break;
#endif

    case 'D':
    if (addr == NULL) goto ADDR_MISMATCH;
    memcpy(&(addr->dsn_aware), ptr, sizeof(addr->dsn_aware));
    ptr += sizeof(addr->dsn_aware);
    DEBUG(D_deliver) debug_printf("DSN read: addr->dsn_aware = %d\n", addr->dsn_aware);
    break;

    case 'A':
    if (addr == NULL)
      {
      ADDR_MISMATCH:
      msg = string_sprintf("address count mismatch for data read from pipe "
        "for transport process %d for transport %s", pid,
          addrlist->transport->driver_name);
      done = TRUE;
      break;
      }

    addr->transport_return = *ptr++;
    addr->special_action = *ptr++;
    memcpy(&(addr->basic_errno), ptr, sizeof(addr->basic_errno));
    ptr += sizeof(addr->basic_errno);
    memcpy(&(addr->more_errno), ptr, sizeof(addr->more_errno));
    ptr += sizeof(addr->more_errno);
    memcpy(&(addr->flags), ptr, sizeof(addr->flags));
    ptr += sizeof(addr->flags);
    addr->message = (*ptr)? string_copy(ptr) : NULL;
    while(*ptr++);
    addr->user_message = (*ptr)? string_copy(ptr) : NULL;
    while(*ptr++);

    /* Always two strings for host information, followed by the port number and DNSSEC mark */

    if (*ptr != 0)
      {
      h = store_get(sizeof(host_item));
      h->name = string_copy(ptr);
      while (*ptr++);
      h->address = string_copy(ptr);
      while(*ptr++);
      memcpy(&(h->port), ptr, sizeof(h->port));
      ptr += sizeof(h->port);
      h->dnssec = *ptr == '2' ? DS_YES
		: *ptr == '1' ? DS_NO
		: DS_UNK;
      ptr++;
      addr->host_used = h;
      }
    else ptr++;

    /* Finished with this address */

    addr = addr->next;
    break;

    /* Local interface address/port */
    case 'I':
    if (*ptr) sending_ip_address = string_copy(ptr);
    while (*ptr++) ;
    if (*ptr) sending_port = atoi(CS ptr);
    while (*ptr++) ;
    break;

    /* Z marks the logical end of the data. It is followed by '0' if
    continue_transport was NULL at the end of transporting, otherwise '1'.
    We need to know when it becomes NULL during a delivery down a passed SMTP
    channel so that we don't try to pass anything more down it. Of course, for
    most normal messages it will remain NULL all the time. */

    case 'Z':
    if (*ptr == '0')
      {
      continue_transport = NULL;
      continue_hostname = NULL;
      }
    done = TRUE;
    DEBUG(D_deliver) debug_printf("Z0%c item read\n", *ptr);
    break;

    /* Anything else is a disaster. */

    default:
    msg = string_sprintf("malformed data (%d) read from pipe for transport "
      "process %d for transport %s", ptr[-1], pid,
        addr->transport->driver_name);
    done = TRUE;
    break;
    }
  }

/* The done flag is inspected externally, to determine whether or not to
call the function again when the process finishes. */

p->done = done;

/* If the process hadn't finished, and we haven't seen the end of the data
or suffered a disaster, update the rest of the state, and return FALSE to
indicate "not finished". */

if (!eop && !done)
  {
  p->addr = addr;
  p->msg = msg;
  return FALSE;
  }

/* Close our end of the pipe, to prevent deadlock if the far end is still
pushing stuff into it. */

(void)close(fd);
p->fd = -1;

/* If we have finished without error, but haven't had data for every address,
something is wrong. */

if (msg == NULL && addr != NULL)
  msg = string_sprintf("insufficient address data read from pipe "
    "for transport process %d for transport %s", pid,
      addr->transport->driver_name);

/* If an error message is set, something has gone wrong in getting back
the delivery data. Put the message into each address and freeze it. */

if (msg != NULL)
  {
  for (addr = addrlist; addr != NULL; addr = addr->next)
    {
    addr->transport_return = DEFER;
    addr->special_action = SPECIAL_FREEZE;
    addr->message = msg;
    }
  }

/* Return TRUE to indicate we have got all we need from this process, even
if it hasn't actually finished yet. */

return TRUE;
}



/*************************************************
*   Post-process a set of remote addresses       *
*************************************************/

/* Do what has to be done immediately after a remote delivery for each set of
addresses, then re-write the spool if necessary. Note that post_process_one
puts the address on an appropriate queue; hence we must fish off the next
one first. This function is also called if there is a problem with setting
up a subprocess to do a remote delivery in parallel. In this case, the final
argument contains a message, and the action must be forced to DEFER.

Argument:
   addr      pointer to chain of address items
   logflags  flags for logging
   msg       NULL for normal cases; -> error message for unexpected problems
   fallback  TRUE if processing fallback hosts

Returns:     nothing
*/

static void
remote_post_process(address_item *addr, int logflags, uschar *msg,
  BOOL fallback)
{
host_item *h;

/* If any host addresses were found to be unusable, add them to the unusable
tree so that subsequent deliveries don't try them. */

for (h = addr->host_list; h != NULL; h = h->next)
  {
  if (h->address == NULL) continue;
  if (h->status >= hstatus_unusable) tree_add_unusable(h);
  }

/* Now handle each address on the chain. The transport has placed '=' or '-'
into the special_action field for each successful delivery. */

while (addr != NULL)
  {
  address_item *next = addr->next;

  /* If msg == NULL (normal processing) and the result is DEFER and we are
  processing the main hosts and there are fallback hosts available, put the
  address on the list for fallback delivery. */

  if (addr->transport_return == DEFER &&
      addr->fallback_hosts != NULL &&
      !fallback &&
      msg == NULL)
    {
    addr->host_list = addr->fallback_hosts;
    addr->next = addr_fallback;
    addr_fallback = addr;
    DEBUG(D_deliver) debug_printf("%s queued for fallback host(s)\n", addr->address);
    }

  /* If msg is set (=> unexpected problem), set it in the address before
  doing the ordinary post processing. */

  else
    {
    if (msg != NULL)
      {
      addr->message = msg;
      addr->transport_return = DEFER;
      }
    (void)post_process_one(addr, addr->transport_return, logflags,
      DTYPE_TRANSPORT, addr->special_action);
    }

  /* Next address */

  addr = next;
  }

/* If we have just delivered down a passed SMTP channel, and that was
the last address, the channel will have been closed down. Now that
we have logged that delivery, set continue_sequence to 1 so that
any subsequent deliveries don't get "*" incorrectly logged. */

if (continue_transport == NULL) continue_sequence = 1;
}



/*************************************************
*     Wait for one remote delivery subprocess    *
*************************************************/

/* This function is called while doing remote deliveries when either the
maximum number of processes exist and we need one to complete so that another
can be created, or when waiting for the last ones to complete. It must wait for
the completion of one subprocess, empty the control block slot, and return a
pointer to the address chain.

Arguments:    none
Returns:      pointer to the chain of addresses handled by the process;
              NULL if no subprocess found - this is an unexpected error
*/

static address_item *
par_wait(void)
{
int poffset, status;
address_item *addr, *addrlist;
pid_t pid;

set_process_info("delivering %s: waiting for a remote delivery subprocess "
  "to finish", message_id);

/* Loop until either a subprocess completes, or there are no subprocesses in
existence - in which case give an error return. We cannot proceed just by
waiting for a completion, because a subprocess may have filled up its pipe, and
be waiting for it to be emptied. Therefore, if no processes have finished, we
wait for one of the pipes to acquire some data by calling select(), with a
timeout just in case.

The simple approach is just to iterate after reading data from a ready pipe.
This leads to non-ideal behaviour when the subprocess has written its final Z
item, closed the pipe, and is in the process of exiting (the common case). A
call to waitpid() yields nothing completed, but select() shows the pipe ready -
reading it yields EOF, so you end up with busy-waiting until the subprocess has
actually finished.

To avoid this, if all the data that is needed has been read from a subprocess
after select(), an explicit wait() for it is done. We know that all it is doing
is writing to the pipe and then exiting, so the wait should not be long.

The non-blocking waitpid() is to some extent just insurance; if we could
reliably detect end-of-file on the pipe, we could always know when to do a
blocking wait() for a completed process. However, because some systems use
NDELAY, which doesn't distinguish between EOF and pipe empty, it is easier to
use code that functions without the need to recognize EOF.

There's a double loop here just in case we end up with a process that is not in
the list of remote delivery processes. Something has obviously gone wrong if
this is the case. (For example, a process that is incorrectly left over from
routing or local deliveries might be found.) The damage can be minimized by
looping back and looking for another process. If there aren't any, the error
return will happen. */

for (;;)   /* Normally we do not repeat this loop */
  {
  while ((pid = waitpid(-1, &status, WNOHANG)) <= 0)
    {
    struct timeval tv;
    fd_set select_pipes;
    int maxpipe, readycount;

    /* A return value of -1 can mean several things. If errno != ECHILD, it
    either means invalid options (which we discount), or that this process was
    interrupted by a signal. Just loop to try the waitpid() again.

    If errno == ECHILD, waitpid() is telling us that there are no subprocesses
    in existence. This should never happen, and is an unexpected error.
    However, there is a nasty complication when running under Linux. If "strace
    -f" is being used under Linux to trace this process and its children,
    subprocesses are "stolen" from their parents and become the children of the
    tracing process. A general wait such as the one we've just obeyed returns
    as if there are no children while subprocesses are running. Once a
    subprocess completes, it is restored to the parent, and waitpid(-1) finds
    it. Thanks to Joachim Wieland for finding all this out and suggesting a
    palliative.

    This does not happen using "truss" on Solaris, nor (I think) with other
    tracing facilities on other OS. It seems to be specific to Linux.

    What we do to get round this is to use kill() to see if any of our
    subprocesses are still in existence. If kill() gives an OK return, we know
    it must be for one of our processes - it can't be for a re-use of the pid,
    because if our process had finished, waitpid() would have found it. If any
    of our subprocesses are in existence, we proceed to use select() as if
    waitpid() had returned zero. I think this is safe. */

    if (pid < 0)
      {
      if (errno != ECHILD) continue;   /* Repeats the waitpid() */

      DEBUG(D_deliver)
        debug_printf("waitpid() returned -1/ECHILD: checking explicitly "
          "for process existence\n");

      for (poffset = 0; poffset < remote_max_parallel; poffset++)
        {
        if ((pid = parlist[poffset].pid) != 0 && kill(pid, 0) == 0)
          {
          DEBUG(D_deliver) debug_printf("process %d still exists: assume "
            "stolen by strace\n", (int)pid);
          break;   /* With poffset set */
          }
        }

      if (poffset >= remote_max_parallel)
        {
        DEBUG(D_deliver) debug_printf("*** no delivery children found\n");
        return NULL;   /* This is the error return */
        }
      }

    /* A pid value greater than 0 breaks the "while" loop. A negative value has
    been handled above. A return value of zero means that there is at least one
    subprocess, but there are no completed subprocesses. See if any pipes are
    ready with any data for reading. */

    DEBUG(D_deliver) debug_printf("selecting on subprocess pipes\n");

    maxpipe = 0;
    FD_ZERO(&select_pipes);
    for (poffset = 0; poffset < remote_max_parallel; poffset++)
      {
      if (parlist[poffset].pid != 0)
        {
        int fd = parlist[poffset].fd;
        FD_SET(fd, &select_pipes);
        if (fd > maxpipe) maxpipe = fd;
        }
      }

    /* Stick in a 60-second timeout, just in case. */

    tv.tv_sec = 60;
    tv.tv_usec = 0;

    readycount = select(maxpipe + 1, (SELECT_ARG2_TYPE *)&select_pipes,
         NULL, NULL, &tv);

    /* Scan through the pipes and read any that are ready; use the count
    returned by select() to stop when there are no more. Select() can return
    with no processes (e.g. if interrupted). This shouldn't matter.

    If par_read_pipe() returns TRUE, it means that either the terminating Z was
    read, or there was a disaster. In either case, we are finished with this
    process. Do an explicit wait() for the process and break the main loop if
    it succeeds.

    It turns out that we have to deal with the case of an interrupted system
    call, which can happen on some operating systems if the signal handling is
    set up to do that by default. */

    for (poffset = 0;
         readycount > 0 && poffset < remote_max_parallel;
         poffset++)
      {
      if ((pid = parlist[poffset].pid) != 0 &&
           FD_ISSET(parlist[poffset].fd, &select_pipes))
        {
        readycount--;
        if (par_read_pipe(poffset, FALSE))    /* Finished with this pipe */
          {
          for (;;)                            /* Loop for signals */
            {
            pid_t endedpid = waitpid(pid, &status, 0);
            if (endedpid == pid) goto PROCESS_DONE;
            if (endedpid != (pid_t)(-1) || errno != EINTR)
              log_write(0, LOG_MAIN|LOG_PANIC_DIE, "Unexpected error return "
                "%d (errno = %d) from waitpid() for process %d",
                (int)endedpid, errno, (int)pid);
            }
          }
        }
      }

    /* Now go back and look for a completed subprocess again. */
    }

  /* A completed process was detected by the non-blocking waitpid(). Find the
  data block that corresponds to this subprocess. */

  for (poffset = 0; poffset < remote_max_parallel; poffset++)
    if (pid == parlist[poffset].pid) break;

  /* Found the data block; this is a known remote delivery process. We don't
  need to repeat the outer loop. This should be what normally happens. */

  if (poffset < remote_max_parallel) break;

  /* This situation is an error, but it's probably better to carry on looking
  for another process than to give up (as we used to do). */

  log_write(0, LOG_MAIN|LOG_PANIC, "Process %d finished: not found in remote "
    "transport process list", pid);
  }  /* End of the "for" loop */

/* Come here when all the data was completely read after a select(), and
the process in pid has been wait()ed for. */

PROCESS_DONE:

DEBUG(D_deliver)
  {
  if (status == 0)
    debug_printf("remote delivery process %d ended\n", (int)pid);
  else
    debug_printf("remote delivery process %d ended: status=%04x\n", (int)pid,
      status);
  }

set_process_info("delivering %s", message_id);

/* Get the chain of processed addresses */

addrlist = parlist[poffset].addrlist;

/* If the process did not finish cleanly, record an error and freeze (except
for SIGTERM, SIGKILL and SIGQUIT), and also ensure the journal is not removed,
in case the delivery did actually happen. */

if ((status & 0xffff) != 0)
  {
  uschar *msg;
  int msb = (status >> 8) & 255;
  int lsb = status & 255;
  int code = (msb == 0)? (lsb & 0x7f) : msb;

  msg = string_sprintf("%s transport process returned non-zero status 0x%04x: "
    "%s %d",
    addrlist->transport->driver_name,
    status,
    (msb == 0)? "terminated by signal" : "exit code",
    code);

  if (msb != 0 || (code != SIGTERM && code != SIGKILL && code != SIGQUIT))
    addrlist->special_action = SPECIAL_FREEZE;

  for (addr = addrlist; addr != NULL; addr = addr->next)
    {
    addr->transport_return = DEFER;
    addr->message = msg;
    }

  remove_journal = FALSE;
  }

/* Else complete reading the pipe to get the result of the delivery, if all
the data has not yet been obtained. */

else if (!parlist[poffset].done) (void)par_read_pipe(poffset, TRUE);

/* Put the data count and return path into globals, mark the data slot unused,
decrement the count of subprocesses, and return the address chain. */

transport_count = parlist[poffset].transport_count;
used_return_path = parlist[poffset].return_path;
parlist[poffset].pid = 0;
parcount--;
return addrlist;
}



/*************************************************
*      Wait for subprocesses and post-process    *
*************************************************/

/* This function waits for subprocesses until the number that are still running
is below a given threshold. For each complete subprocess, the addresses are
post-processed. If we can't find a running process, there is some shambles.
Better not bomb out, as that might lead to multiple copies of the message. Just
log and proceed as if all done.

Arguments:
  max         maximum number of subprocesses to leave running
  fallback    TRUE if processing fallback hosts

Returns:      nothing
*/

static void
par_reduce(int max, BOOL fallback)
{
while (parcount > max)
  {
  address_item *doneaddr = par_wait();
  if (doneaddr == NULL)
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
      "remote delivery process count got out of step");
    parcount = 0;
    }
  else remote_post_process(doneaddr, LOG_MAIN, NULL, fallback);
  }
}




static void
rmt_dlv_checked_write(int fd, char id, char subid, void * buf, int size)
{
uschar	writebuffer[PIPE_HEADER_SIZE + BIG_BUFFER_SIZE];
int     header_length;

/* we assume that size can't get larger then BIG_BUFFER_SIZE which currently is set to 16k */
/* complain to log if someone tries with buffer sizes we can't handle*/

if (size > 99999)
{
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, 
    "Failed writing transport result to pipe: can't handle buffers > 99999 bytes. truncating!\n");
  size = 99999;
}

/* to keep the write() atomic we build header in writebuffer and copy buf behind */
/* two write() calls would increase the complexity of reading from pipe */

/* convert size to human readable string prepended by id and subid */
header_length = snprintf(CS writebuffer, PIPE_HEADER_SIZE+1, "%c%c%05d", id, subid, size);
if (header_length != PIPE_HEADER_SIZE)
{
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "header snprintf failed\n");
  writebuffer[0] = '\0';
}

DEBUG(D_deliver) debug_printf("header write id:%c,subid:%c,size:%d,final:%s\n", 
                                 id, subid, size, writebuffer);

if (buf && size > 0)
  memcpy(writebuffer + PIPE_HEADER_SIZE, buf, size);

size += PIPE_HEADER_SIZE;
int ret = write(fd, writebuffer, size);
if(ret != size)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "Failed writing transport result to pipe: %s\n",
    ret == -1 ? strerror(errno) : "short write");
}

/*************************************************
*           Do remote deliveries                 *
*************************************************/

/* This function is called to process the addresses in addr_remote. We must
pick off the queue all addresses that have the same transport, remote
destination, and errors address, and hand them to the transport in one go,
subject to some configured limitations. If this is a run to continue delivering
to an existing delivery channel, skip all but those addresses that can go to
that channel. The skipped addresses just get deferred.

If mua_wrapper is set, all addresses must be able to be sent in a single
transaction. If not, this function yields FALSE.

In Exim 4, remote deliveries are always done in separate processes, even
if remote_max_parallel = 1 or if there's only one delivery to do. The reason
is so that the base process can retain privilege. This makes the
implementation of fallback transports feasible (though not initially done.)

We create up to the configured number of subprocesses, each of which passes
back the delivery state via a pipe. (However, when sending down an existing
connection, remote_max_parallel is forced to 1.)

Arguments:
  fallback  TRUE if processing fallback hosts

Returns:    TRUE normally
            FALSE if mua_wrapper is set and the addresses cannot all be sent
              in one transaction
*/

static BOOL
do_remote_deliveries(BOOL fallback)
{
int parmax;
int delivery_count;
int poffset;

parcount = 0;    /* Number of executing subprocesses */

/* When sending down an existing channel, only do one delivery at a time.
We use a local variable (parmax) to hold the maximum number of processes;
this gets reduced from remote_max_parallel if we can't create enough pipes. */

if (continue_transport != NULL) remote_max_parallel = 1;
parmax = remote_max_parallel;

/* If the data for keeping a list of processes hasn't yet been
set up, do so. */

if (parlist == NULL)
  {
  parlist = store_get(remote_max_parallel * sizeof(pardata));
  for (poffset = 0; poffset < remote_max_parallel; poffset++)
    parlist[poffset].pid = 0;
  }

/* Now loop for each remote delivery */

for (delivery_count = 0; addr_remote != NULL; delivery_count++)
  {
  pid_t pid;
  uid_t uid;
  gid_t gid;
  int pfd[2];
  int address_count = 1;
  int address_count_max;
  BOOL multi_domain;
  BOOL use_initgroups;
  BOOL pipe_done = FALSE;
  transport_instance *tp;
  address_item **anchor = &addr_remote;
  address_item *addr = addr_remote;
  address_item *last = addr;
  address_item *next;

  /* Pull the first address right off the list. */

  addr_remote = addr->next;
  addr->next = NULL;

  DEBUG(D_deliver|D_transport)
    debug_printf("--------> %s <--------\n", addr->address);

  /* If no transport has been set, there has been a big screw-up somewhere. */

  if ((tp = addr->transport) == NULL)
    {
    disable_logging = FALSE;  /* Jic */
    remote_post_process(addr, LOG_MAIN|LOG_PANIC,
      US"No transport set by router", fallback);
    continue;
    }

  /* Check that this base address hasn't previously been delivered to this
  transport. The check is necessary at this point to handle homonymic addresses
  correctly in cases where the pattern of redirection changes between delivery
  attempts. Non-homonymic previous delivery is detected earlier, at routing
  time. */

  if (previously_transported(addr, FALSE)) continue;

  /* Force failure if the message is too big. */

  if (tp->message_size_limit != NULL)
    {
    int rc = check_message_size(tp, addr);
    if (rc != OK)
      {
      addr->transport_return = rc;
      remote_post_process(addr, LOG_MAIN, NULL, fallback);
      continue;
      }
    }

  /* Get the flag which specifies whether the transport can handle different
  domains that nevertheless resolve to the same set of hosts. If it needs
  expanding, get variables set: $address_data, $domain_data, $localpart_data,
  $host, $host_address, $host_port. */
  if (tp->expand_multi_domain)
    deliver_set_expansions(addr);

  if (exp_bool(addr, US"transport", tp->name, D_transport,
		US"multi_domain", tp->multi_domain, tp->expand_multi_domain,
		&multi_domain) != OK)
    {
    deliver_set_expansions(NULL);
    remote_post_process(addr, LOG_MAIN|LOG_PANIC, addr->message, fallback);
    continue;
    }

  /* Get the maximum it can handle in one envelope, with zero meaning
  unlimited, which is forced for the MUA wrapper case. */

  address_count_max = tp->max_addresses;
  if (address_count_max == 0 || mua_wrapper) address_count_max = 999999;


  /************************************************************************/
  /*****    This is slightly experimental code, but should be safe.   *****/

  /* The address_count_max value is the maximum number of addresses that the
  transport can send in one envelope. However, the transport must be capable of
  dealing with any number of addresses. If the number it gets exceeds its
  envelope limitation, it must send multiple copies of the message. This can be
  done over a single connection for SMTP, so uses less resources than making
  multiple connections. On the other hand, if remote_max_parallel is greater
  than one, it is perhaps a good idea to use parallel processing to move the
  message faster, even if that results in multiple simultaneous connections to
  the same host.

  How can we come to some compromise between these two ideals? What we do is to
  limit the number of addresses passed to a single instance of a transport to
  the greater of (a) its address limit (rcpt_max for SMTP) and (b) the total
  number of addresses routed to remote transports divided by
  remote_max_parallel. For example, if the message has 100 remote recipients,
  remote max parallel is 2, and rcpt_max is 10, we'd never send more than 50 at
  once. But if rcpt_max is 100, we could send up to 100.

  Of course, not all the remotely addresses in a message are going to go to the
  same set of hosts (except in smarthost configurations), so this is just a
  heuristic way of dividing up the work.

  Furthermore (1), because this may not be wanted in some cases, and also to
  cope with really pathological cases, there is also a limit to the number of
  messages that are sent over one connection. This is the same limit that is
  used when sending several different messages over the same connection.
  Continue_sequence is set when in this situation, to the number sent so
  far, including this message.

  Furthermore (2), when somebody explicitly sets the maximum value to 1, it
  is probably because they are using VERP, in which case they want to pass only
  one address at a time to the transport, in order to be able to use
  $local_part and $domain in constructing a new return path. We could test for
  the use of these variables, but as it is so likely they will be used when the
  maximum is 1, we don't bother. Just leave the value alone. */

  if (address_count_max != 1 &&
      address_count_max < remote_delivery_count/remote_max_parallel)
    {
    int new_max = remote_delivery_count/remote_max_parallel;
    int message_max = tp->connection_max_messages;
    if (connection_max_messages >= 0) message_max = connection_max_messages;
    message_max -= continue_sequence - 1;
    if (message_max > 0 && new_max > address_count_max * message_max)
      new_max = address_count_max * message_max;
    address_count_max = new_max;
    }

  /************************************************************************/


  /* Pick off all addresses which have the same transport, errors address,
  destination, and extra headers. In some cases they point to the same host
  list, but we also need to check for identical host lists generated from
  entirely different domains. The host list pointers can be NULL in the case
  where the hosts are defined in the transport. There is also a configured
  maximum limit of addresses that can be handled at once (see comments above
  for how it is computed).
  If the transport does not handle multiple domains, enforce that also,
  and if it might need a per-address check for this, re-evaluate it.
  */

  while ((next = *anchor) != NULL && address_count < address_count_max)
    {
    BOOL md;
    if (  (multi_domain || Ustrcmp(next->domain, addr->domain) == 0)
       && tp == next->transport
       && same_hosts(next->host_list, addr->host_list)
       && same_strings(next->prop.errors_address, addr->prop.errors_address)
       && same_headers(next->prop.extra_headers, addr->prop.extra_headers)
       && same_ugid(tp, next, addr)
       && (  next->prop.remove_headers == addr->prop.remove_headers
	  || (  next->prop.remove_headers
	     && addr->prop.remove_headers
	     && Ustrcmp(next->prop.remove_headers, addr->prop.remove_headers) == 0
	  )  )
       && (  !multi_domain
	  || (  (
		!tp->expand_multi_domain || (deliver_set_expansions(next), 1),
	        exp_bool(addr,
		    US"transport", next->transport->name, D_transport,
		    US"multi_domain", next->transport->multi_domain,
		    next->transport->expand_multi_domain, &md) == OK
	        )
	     && md
       )  )  )
      {
      *anchor = next->next;
      next->next = NULL;
      next->first = addr;  /* remember top one (for retry processing) */
      last->next = next;
      last = next;
      address_count++;
      }
    else anchor = &(next->next);
    deliver_set_expansions(NULL);
    }

  /* If we are acting as an MUA wrapper, all addresses must go in a single
  transaction. If not, put them back on the chain and yield FALSE. */

  if (mua_wrapper && addr_remote != NULL)
    {
    last->next = addr_remote;
    addr_remote = addr;
    return FALSE;
    }

  /* Set up the expansion variables for this set of addresses */

  deliver_set_expansions(addr);

  /* Ensure any transport-set auth info is fresh */
  addr->authenticator = addr->auth_id = addr->auth_sndr = NULL;

  /* Compute the return path, expanding a new one if required. The old one
  must be set first, as it might be referred to in the expansion. */

  if(addr->prop.errors_address != NULL)
    return_path = addr->prop.errors_address;
#ifdef EXPERIMENTAL_SRS
  else if(addr->prop.srs_sender != NULL)
    return_path = addr->prop.srs_sender;
#endif
  else
    return_path = sender_address;

  if (tp->return_path != NULL)
    {
    uschar *new_return_path = expand_string(tp->return_path);
    if (new_return_path == NULL)
      {
      if (!expand_string_forcedfail)
        {
        remote_post_process(addr, LOG_MAIN|LOG_PANIC,
          string_sprintf("Failed to expand return path \"%s\": %s",
          tp->return_path, expand_string_message), fallback);
        continue;
        }
      }
    else return_path = new_return_path;
    }

  /* Find the uid, gid, and use_initgroups setting for this transport. Failure
  logs and sets up error messages, so we just post-process and continue with
  the next address. */

  if (!findugid(addr, tp, &uid, &gid, &use_initgroups))
    {
    remote_post_process(addr, LOG_MAIN|LOG_PANIC, NULL, fallback);
    continue;
    }

  /* If this transport has a setup function, call it now so that it gets
  run in this process and not in any subprocess. That way, the results of
  any setup that are retained by the transport can be reusable. One of the
  things the setup does is to set the fallback host lists in the addresses.
  That is why it is called at this point, before the continue delivery
  processing, because that might use the fallback hosts. */

  if (tp->setup != NULL)
    (void)((tp->setup)(addr->transport, addr, NULL, uid, gid, NULL));

  /* If this is a run to continue delivery down an already-established
  channel, check that this set of addresses matches the transport and
  the channel. If it does not, defer the addresses. If a host list exists,
  we must check that the continue host is on the list. Otherwise, the
  host is set in the transport. */

  continue_more = FALSE;           /* In case got set for the last lot */
  if (continue_transport != NULL)
    {
    BOOL ok = Ustrcmp(continue_transport, tp->name) == 0;
    if (ok && addr->host_list != NULL)
      {
      host_item *h;
      ok = FALSE;
      for (h = addr->host_list; h != NULL; h = h->next)
        {
        if (Ustrcmp(h->name, continue_hostname) == 0)
          { ok = TRUE; break; }
        }
      }

    /* Addresses not suitable; defer or queue for fallback hosts (which
    might be the continue host) and skip to next address. */

    if (!ok)
      {
      DEBUG(D_deliver) debug_printf("not suitable for continue_transport\n");
      next = addr;

      if (addr->fallback_hosts != NULL && !fallback)
        {
        for (;;)
          {
          next->host_list = next->fallback_hosts;
          DEBUG(D_deliver) debug_printf("%s queued for fallback host(s)\n", next->address);
          if (next->next == NULL) break;
          next = next->next;
          }
        next->next = addr_fallback;
        addr_fallback = addr;
        }

      else
        {
        while (next->next != NULL) next = next->next;
        next->next = addr_defer;
        addr_defer = addr;
        }

      continue;
      }

    /* Set a flag indicating whether there are further addresses that list
    the continued host. This tells the transport to leave the channel open,
    but not to pass it to another delivery process. */

    for (next = addr_remote; next != NULL; next = next->next)
      {
      host_item *h;
      for (h = next->host_list; h != NULL; h = h->next)
        {
        if (Ustrcmp(h->name, continue_hostname) == 0)
          { continue_more = TRUE; break; }
        }
      }
    }

  /* The transports set up the process info themselves as they may connect
  to more than one remote machine. They also have to set up the filter
  arguments, if required, so that the host name and address are available
  for expansion. */

  transport_filter_argv = NULL;

  /* Create the pipe for inter-process communication. If pipe creation
  fails, it is probably because the value of remote_max_parallel is so
  large that too many file descriptors for pipes have been created. Arrange
  to wait for a process to finish, and then try again. If we still can't
  create a pipe when all processes have finished, break the retry loop. */

  while (!pipe_done)
    {
    if (pipe(pfd) == 0) pipe_done = TRUE;
      else if (parcount > 0) parmax = parcount;
        else break;

    /* We need to make the reading end of the pipe non-blocking. There are
    two different options for this. Exim is cunningly (I hope!) coded so
    that it can use either of them, though it prefers O_NONBLOCK, which
    distinguishes between EOF and no-more-data. */

#ifdef O_NONBLOCK
    (void)fcntl(pfd[pipe_read], F_SETFL, O_NONBLOCK);
#else
    (void)fcntl(pfd[pipe_read], F_SETFL, O_NDELAY);
#endif

    /* If the maximum number of subprocesses already exist, wait for a process
    to finish. If we ran out of file descriptors, parmax will have been reduced
    from its initial value of remote_max_parallel. */

    par_reduce(parmax - 1, fallback);
    }

  /* If we failed to create a pipe and there were no processes to wait
  for, we have to give up on this one. Do this outside the above loop
  so that we can continue the main loop. */

  if (!pipe_done)
    {
    remote_post_process(addr, LOG_MAIN|LOG_PANIC,
      string_sprintf("unable to create pipe: %s", strerror(errno)), fallback);
    continue;
    }

  /* Find a free slot in the pardata list. Must do this after the possible
  waiting for processes to finish, because a terminating process will free
  up a slot. */

  for (poffset = 0; poffset < remote_max_parallel; poffset++)
    if (parlist[poffset].pid == 0) break;

  /* If there isn't one, there has been a horrible disaster. */

  if (poffset >= remote_max_parallel)
    {
    (void)close(pfd[pipe_write]);
    (void)close(pfd[pipe_read]);
    remote_post_process(addr, LOG_MAIN|LOG_PANIC,
      US"Unexpectedly no free subprocess slot", fallback);
    continue;
    }

  /* Now fork a subprocess to do the remote delivery, but before doing so,
  ensure that any cached resourses are released so as not to interfere with
  what happens in the subprocess. */

  search_tidyup();

  if ((pid = fork()) == 0)
    {
    int fd = pfd[pipe_write];
    host_item *h;

    /* Setting this global in the subprocess means we need never clear it */
    transport_name = tp->name;

    /* There are weird circumstances in which logging is disabled */
    disable_logging = tp->disable_logging;

    /* Show pids on debug output if parallelism possible */

    if (parmax > 1 && (parcount > 0 || addr_remote != NULL))
      {
      DEBUG(D_any|D_v) debug_selector |= D_pid;
      DEBUG(D_deliver) debug_printf("Remote delivery process started\n");
      }

    /* Reset the random number generator, so different processes don't all
    have the same sequence. In the test harness we want different, but
    predictable settings for each delivery process, so do something explicit
    here rather they rely on the fixed reset in the random number function. */

    random_seed = running_in_test_harness? 42 + 2*delivery_count : 0;

    /* Set close-on-exec on the pipe so that it doesn't get passed on to
    a new process that may be forked to do another delivery down the same
    SMTP connection. */

    (void)fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);

    /* Close open file descriptors for the pipes of other processes
    that are running in parallel. */

    for (poffset = 0; poffset < remote_max_parallel; poffset++)
      if (parlist[poffset].pid != 0) (void)close(parlist[poffset].fd);

    /* This process has inherited a copy of the file descriptor
    for the data file, but its file pointer is shared with all the
    other processes running in parallel. Therefore, we have to re-open
    the file in order to get a new file descriptor with its own
    file pointer. We don't need to lock it, as the lock is held by
    the parent process. There doesn't seem to be any way of doing
    a dup-with-new-file-pointer. */

    (void)close(deliver_datafile);
    sprintf(CS spoolname, "%s/input/%s/%s-D", spool_directory, message_subdir,
      message_id);
    deliver_datafile = Uopen(spoolname, O_RDWR | O_APPEND, 0);

    if (deliver_datafile < 0)
      log_write(0, LOG_MAIN|LOG_PANIC_DIE, "Failed to reopen %s for remote "
        "parallel delivery: %s", spoolname, strerror(errno));

    /* Set the close-on-exec flag */

    (void)fcntl(deliver_datafile, F_SETFD, fcntl(deliver_datafile, F_GETFD) |
      FD_CLOEXEC);

    /* Set the uid/gid of this process; bombs out on failure. */

    exim_setugid(uid, gid, use_initgroups,
      string_sprintf("remote delivery to %s with transport=%s",
        addr->address, tp->name));

    /* Close the unwanted half of this process' pipe, set the process state,
    and run the transport. Afterwards, transport_count will contain the number
    of bytes written. */

    (void)close(pfd[pipe_read]);
    set_process_info("delivering %s using %s", message_id, tp->name);
    debug_print_string(tp->debug_string);
    if (!(tp->info->code)(addr->transport, addr)) replicate_status(addr);

    set_process_info("delivering %s (just run %s for %s%s in subprocess)",
      message_id, tp->name, addr->address, (addr->next == NULL)? "" : ", ...");

    /* Ensure any cached resources that we used are now released */

    search_tidyup();

    /* Pass the result back down the pipe. This is a lot more information
    than is needed for a local delivery. We have to send back the error
    status for each address, the usability status for each host that is
    flagged as unusable, and all the retry items. When TLS is in use, we
    send also the cipher and peerdn information. Each type of information
    is flagged by an identifying byte, and is then in a fixed format (with
    strings terminated by zeros), and there is a final terminator at the
    end. The host information and retry information is all attached to
    the first address, so that gets sent at the start. */

    /* Host unusability information: for most success cases this will
    be null. */

    for (h = addr->host_list; h != NULL; h = h->next)
      {
      if (h->address == NULL || h->status < hstatus_unusable) continue;
      sprintf(CS big_buffer, "%c%c%s", h->status, h->why, h->address);
      rmt_dlv_checked_write(fd, 'H', '0', big_buffer, Ustrlen(big_buffer+2) + 3);
      }

    /* The number of bytes written. This is the same for each address. Even
    if we sent several copies of the message down the same connection, the
    size of each one is the same, and it's that value we have got because
    transport_count gets reset before calling transport_write_message(). */

    memcpy(big_buffer, &transport_count, sizeof(transport_count));
    rmt_dlv_checked_write(fd, 'S', '0', big_buffer, sizeof(transport_count));

    /* Information about what happened to each address. Four item types are
    used: an optional 'X' item first, for TLS information, then an optional "C"
    item for any client-auth info followed by 'R' items for any retry settings,
    and finally an 'A' item for the remaining data. */

    for(; addr != NULL; addr = addr->next)
      {
      uschar *ptr;
      retry_item *r;

      /* The certificate verification status goes into the flags */
      if (tls_out.certificate_verified) setflag(addr, af_cert_verified);
#ifdef EXPERIMENTAL_DANE
      if (tls_out.dane_verified)        setflag(addr, af_dane_verified);
#endif

      /* Use an X item only if there's something to send */
#ifdef SUPPORT_TLS
      if (addr->cipher)
        {
        ptr = big_buffer;
        sprintf(CS ptr, "%.128s", addr->cipher);
        while(*ptr++);
        if (!addr->peerdn)
	  *ptr++ = 0;
	else
          {
          sprintf(CS ptr, "%.512s", addr->peerdn);
          while(*ptr++);
          }

        rmt_dlv_checked_write(fd, 'X', '1', big_buffer, ptr - big_buffer);
        }
      if (addr->peercert)
	{
        ptr = big_buffer;
	if (!tls_export_cert(ptr, big_buffer_size-2, addr->peercert))
	  while(*ptr++);
	else
	  *ptr++ = 0;
        rmt_dlv_checked_write(fd, 'X', '2', big_buffer, ptr - big_buffer);
	}
      if (addr->ourcert)
	{
        ptr = big_buffer;
	if (!tls_export_cert(ptr, big_buffer_size-2, addr->ourcert))
	  while(*ptr++);
	else
	  *ptr++ = 0;
        rmt_dlv_checked_write(fd, 'X', '3', big_buffer, ptr - big_buffer);
	}
# ifndef DISABLE_OCSP
      if (addr->ocsp > OCSP_NOT_REQ)
	{
	ptr = big_buffer;
	sprintf(CS ptr, "%c", addr->ocsp + '0');
	while(*ptr++);
        rmt_dlv_checked_write(fd, 'X', '4', big_buffer, ptr - big_buffer);
	}
# endif
#endif	/*SUPPORT_TLS*/

      if (client_authenticator)
        {
        ptr = big_buffer;
	sprintf(CS big_buffer, "%.64s", client_authenticator);
        while(*ptr++);
        rmt_dlv_checked_write(fd, 'C', '1', big_buffer, ptr - big_buffer);
	}
      if (client_authenticated_id)
        {
        ptr = big_buffer;
	sprintf(CS big_buffer, "%.64s", client_authenticated_id);
        while(*ptr++);
        rmt_dlv_checked_write(fd, 'C', '2', big_buffer, ptr - big_buffer);
	}
      if (client_authenticated_sender)
        {
        ptr = big_buffer;
	sprintf(CS big_buffer, "%.64s", client_authenticated_sender);
        while(*ptr++);
        rmt_dlv_checked_write(fd, 'C', '3', big_buffer, ptr - big_buffer);
	}

#ifndef DISABLE_PRDR
      if (addr->flags & af_prdr_used)
	rmt_dlv_checked_write(fd, 'P', '0', NULL, 0);
#endif

      memcpy(big_buffer, &addr->dsn_aware, sizeof(addr->dsn_aware));
      rmt_dlv_checked_write(fd, 'D', '0', big_buffer, sizeof(addr->dsn_aware));
      DEBUG(D_deliver) debug_printf("DSN write: addr->dsn_aware = %d\n", addr->dsn_aware);

      /* Retry information: for most success cases this will be null. */

      for (r = addr->retries; r != NULL; r = r->next)
        {
        uschar *ptr;
        sprintf(CS big_buffer, "%c%.500s", r->flags, r->key);
        ptr = big_buffer + Ustrlen(big_buffer+2) + 3;
        memcpy(ptr, &(r->basic_errno), sizeof(r->basic_errno));
        ptr += sizeof(r->basic_errno);
        memcpy(ptr, &(r->more_errno), sizeof(r->more_errno));
        ptr += sizeof(r->more_errno);
        if (r->message == NULL) *ptr++ = 0; else
          {
          sprintf(CS ptr, "%.512s", r->message);
          while(*ptr++);
          }
        rmt_dlv_checked_write(fd, 'R', '0', big_buffer, ptr - big_buffer);
        }

      /* The rest of the information goes in an 'A' item. */

      ptr = big_buffer + 2;
      sprintf(CS big_buffer, "%c%c", addr->transport_return,
        addr->special_action);
      memcpy(ptr, &(addr->basic_errno), sizeof(addr->basic_errno));
      ptr += sizeof(addr->basic_errno);
      memcpy(ptr, &(addr->more_errno), sizeof(addr->more_errno));
      ptr += sizeof(addr->more_errno);
      memcpy(ptr, &(addr->flags), sizeof(addr->flags));
      ptr += sizeof(addr->flags);

      if (addr->message == NULL) *ptr++ = 0; else
        {
        sprintf(CS ptr, "%.1024s", addr->message);
        while(*ptr++);
        }

      if (addr->user_message == NULL) *ptr++ = 0; else
        {
        sprintf(CS ptr, "%.1024s", addr->user_message);
        while(*ptr++);
        }

      if (addr->host_used == NULL) *ptr++ = 0; else
        {
        sprintf(CS ptr, "%.256s", addr->host_used->name);
        while(*ptr++);
        sprintf(CS ptr, "%.64s", addr->host_used->address);
        while(*ptr++);
        memcpy(ptr, &(addr->host_used->port), sizeof(addr->host_used->port));
        ptr += sizeof(addr->host_used->port);

        /* DNS lookup status */
	*ptr++ = addr->host_used->dnssec==DS_YES ? '2'
	       : addr->host_used->dnssec==DS_NO ? '1' : '0';

        }
      rmt_dlv_checked_write(fd, 'A', '0', big_buffer, ptr - big_buffer);
      }

    /* Local interface address/port */
    if (log_extra_selector & LX_incoming_interface  &&  sending_ip_address)
      {
      uschar * ptr = big_buffer;
      sprintf(CS ptr, "%.128s", sending_ip_address);
      while(*ptr++);
      sprintf(CS ptr, "%d", sending_port);
      while(*ptr++);

      rmt_dlv_checked_write(fd, 'I', '0', big_buffer, ptr - big_buffer);
      }

    /* Add termination flag, close the pipe, and that's it. The character
    after 'Z' indicates whether continue_transport is now NULL or not.
    A change from non-NULL to NULL indicates a problem with a continuing
    connection. */

    big_buffer[0] = (continue_transport == NULL)? '0' : '1';
    rmt_dlv_checked_write(fd, 'Z', '0', big_buffer, 1);
    (void)close(fd);
    exit(EXIT_SUCCESS);
    }

  /* Back in the mainline: close the unwanted half of the pipe. */

  (void)close(pfd[pipe_write]);

  /* Fork failed; defer with error message */

  if (pid < 0)
    {
    (void)close(pfd[pipe_read]);
    remote_post_process(addr, LOG_MAIN|LOG_PANIC,
      string_sprintf("fork failed for remote delivery to %s: %s",
        addr->domain, strerror(errno)), fallback);
    continue;
    }

  /* Fork succeeded; increment the count, and remember relevant data for
  when the process finishes. */

  parcount++;
  parlist[poffset].addrlist = parlist[poffset].addr = addr;
  parlist[poffset].pid = pid;
  parlist[poffset].fd = pfd[pipe_read];
  parlist[poffset].done = FALSE;
  parlist[poffset].msg = NULL;
  parlist[poffset].return_path = return_path;

  /* If the process we've just started is sending a message down an existing
  channel, wait for it now. This ensures that only one such process runs at
  once, whatever the value of remote_max parallel. Otherwise, we might try to
  send two or more messages simultaneously down the same channel. This could
  happen if there are different domains that include the same host in otherwise
  different host lists.

  Also, if the transport closes down the channel, this information gets back
  (continue_transport gets set to NULL) before we consider any other addresses
  in this message. */

  if (continue_transport != NULL) par_reduce(0, fallback);

  /* Otherwise, if we are running in the test harness, wait a bit, to let the
  newly created process get going before we create another process. This should
  ensure repeatability in the tests. We only need to wait a tad. */

  else if (running_in_test_harness) millisleep(500);
  }

/* Reached the end of the list of addresses. Wait for all the subprocesses that
are still running and post-process their addresses. */

par_reduce(0, fallback);
return TRUE;
}




/*************************************************
*   Split an address into local part and domain  *
*************************************************/

/* This function initializes an address for routing by splitting it up into a
local part and a domain. The local part is set up twice - once in its original
casing, and once in lower case, and it is dequoted. We also do the "percent
hack" for configured domains. This may lead to a DEFER result if a lookup
defers. When a percent-hacking takes place, we insert a copy of the original
address as a new parent of this address, as if we have had a redirection.

Argument:
  addr      points to an addr_item block containing the address

Returns:    OK
            DEFER   - could not determine if domain is %-hackable
*/

int
deliver_split_address(address_item *addr)
{
uschar *address = addr->address;
uschar *domain = Ustrrchr(address, '@');
uschar *t;
int len = domain - address;

addr->domain = string_copylc(domain+1);    /* Domains are always caseless */

/* The implication in the RFCs (though I can't say I've seen it spelled out
explicitly) is that quoting should be removed from local parts at the point
where they are locally interpreted. [The new draft "821" is more explicit on
this, Jan 1999.] We know the syntax is valid, so this can be done by simply
removing quoting backslashes and any unquoted doublequotes. */

t = addr->cc_local_part = store_get(len+1);
while(len-- > 0)
  {
  register int c = *address++;
  if (c == '\"') continue;
  if (c == '\\')
    {
    *t++ = *address++;
    len--;
    }
  else *t++ = c;
  }
*t = 0;

/* We do the percent hack only for those domains that are listed in
percent_hack_domains. A loop is required, to copy with multiple %-hacks. */

if (percent_hack_domains != NULL)
  {
  int rc;
  uschar *new_address = NULL;
  uschar *local_part = addr->cc_local_part;

  deliver_domain = addr->domain;  /* set $domain */

  while ((rc = match_isinlist(deliver_domain, (const uschar **)&percent_hack_domains, 0,
           &domainlist_anchor, addr->domain_cache, MCL_DOMAIN, TRUE, NULL))
             == OK &&
         (t = Ustrrchr(local_part, '%')) != NULL)
    {
    new_address = string_copy(local_part);
    new_address[t - local_part] = '@';
    deliver_domain = string_copylc(t+1);
    local_part = string_copyn(local_part, t - local_part);
    }

  if (rc == DEFER) return DEFER;   /* lookup deferred */

  /* If hackery happened, set up new parent and alter the current address. */

  if (new_address != NULL)
    {
    address_item *new_parent = store_get(sizeof(address_item));
    *new_parent = *addr;
    addr->parent = new_parent;
    addr->address = new_address;
    addr->unique = string_copy(new_address);
    addr->domain = deliver_domain;
    addr->cc_local_part = local_part;
    DEBUG(D_deliver) debug_printf("%%-hack changed address to: %s\n",
      addr->address);
    }
  }

/* Create the lowercased version of the final local part, and make that the
default one to be used. */

addr->local_part = addr->lc_local_part = string_copylc(addr->cc_local_part);
return OK;
}




/*************************************************
*      Get next error message text               *
*************************************************/

/* If f is not NULL, read the next "paragraph", from a customized error message
text file, terminated by a line containing ****, and expand it.

Arguments:
  f          NULL or a file to read from
  which      string indicating which string (for errors)

Returns:     NULL or an expanded string
*/

static uschar *
next_emf(FILE *f, uschar *which)
{
int size = 256;
int ptr = 0;
uschar *para, *yield;
uschar buffer[256];

if (f == NULL) return NULL;

if (Ufgets(buffer, sizeof(buffer), f) == NULL ||
    Ustrcmp(buffer, "****\n") == 0) return NULL;

para = store_get(size);
for (;;)
  {
  para = string_cat(para, &size, &ptr, buffer, Ustrlen(buffer));
  if (Ufgets(buffer, sizeof(buffer), f) == NULL ||
      Ustrcmp(buffer, "****\n") == 0) break;
  }
para[ptr] = 0;

yield = expand_string(para);
if (yield != NULL) return yield;

log_write(0, LOG_MAIN|LOG_PANIC, "Failed to expand string from "
  "bounce_message_file or warn_message_file (%s): %s", which,
  expand_string_message);
return NULL;
}




/*************************************************
*      Close down a passed transport channel     *
*************************************************/

/* This function is called when a passed transport channel cannot be used.
It attempts to close it down tidily. The yield is always DELIVER_NOT_ATTEMPTED
so that the function call can be the argument of a "return" statement.

Arguments:  None
Returns:    DELIVER_NOT_ATTEMPTED
*/

static int
continue_closedown(void)
{
if (continue_transport != NULL)
  {
  transport_instance *t;
  for (t = transports; t != NULL; t = t->next)
    {
    if (Ustrcmp(t->name, continue_transport) == 0)
      {
      if (t->info->closedown != NULL) (t->info->closedown)(t);
      break;
      }
    }
  }
return DELIVER_NOT_ATTEMPTED;
}




/*************************************************
*           Print address information            *
*************************************************/

/* This function is called to output an address, or information about an
address, for bounce or defer messages. If the hide_child flag is set, all we
output is the original ancestor address.

Arguments:
  addr         points to the address
  f            the FILE to print to
  si           an initial string
  sc           a continuation string for before "generated"
  se           an end string

Returns:       TRUE if the address is not hidden
*/

static BOOL
print_address_information(address_item *addr, FILE *f, uschar *si, uschar *sc,
  uschar *se)
{
BOOL yield = TRUE;
uschar *printed = US"";
address_item *ancestor = addr;
while (ancestor->parent != NULL) ancestor = ancestor->parent;

fprintf(f, "%s", CS si);

if (addr->parent != NULL && testflag(addr, af_hide_child))
  {
  printed = US"an undisclosed address";
  yield = FALSE;
  }
else if (!testflag(addr, af_pfr) || addr->parent == NULL)
  printed = addr->address;

else
  {
  uschar *s = addr->address;
  uschar *ss;

  if (addr->address[0] == '>') { ss = US"mail"; s++; }
  else if (addr->address[0] == '|') ss = US"pipe";
  else ss = US"save";

  fprintf(f, "%s to %s%sgenerated by ", ss, s, sc);
  printed = addr->parent->address;
  }

fprintf(f, "%s", CS string_printing(printed));

if (ancestor != addr)
  {
  uschar *original = (ancestor->onetime_parent == NULL)?
    ancestor->address : ancestor->onetime_parent;
  if (strcmpic(original, printed) != 0)
    fprintf(f, "%s(%sgenerated from %s)", sc,
      (ancestor != addr->parent)? "ultimately " : "",
      string_printing(original));
  }

if (addr->host_used)
  fprintf(f, "\n    host %s [%s]",
	  addr->host_used->name, addr->host_used->address);

fprintf(f, "%s", CS se);
return yield;
}





/*************************************************
*         Print error for an address             *
*************************************************/

/* This function is called to print the error information out of an address for
a bounce or a warning message. It tries to format the message reasonably by
introducing newlines. All lines are indented by 4; the initial printing
position must be set before calling.

This function used always to print the error. Nowadays we want to restrict it
to cases such as LMTP/SMTP errors from a remote host, and errors from :fail:
and filter "fail". We no longer pass other information willy-nilly in bounce
and warning messages. Text in user_message is always output; text in message
only if the af_pass_message flag is set.

Arguments:
  addr         the address
  f            the FILE to print on
  t            some leading text

Returns:       nothing
*/

static void
print_address_error(address_item *addr, FILE *f, uschar *t)
{
int count = Ustrlen(t);
uschar *s = testflag(addr, af_pass_message)? addr->message : NULL;

if (!s && !(s = addr->user_message))
  return;

fprintf(f, "\n    %s", t);

while (*s)
  if (*s == '\\' && s[1] == 'n')
    {
    fprintf(f, "\n    ");
    s += 2;
    count = 0;
    }
  else
    {
    fputc(*s, f);
    count++;
    if (*s++ == ':' && isspace(*s) && count > 45)
      {
      fprintf(f, "\n   ");  /* sic (because space follows) */
      count = 0;
      }
    }
}


/***********************************************************
*         Print Diagnostic-Code for an address             *
************************************************************/

/* This function is called to print the error information out of an address for
a bounce or a warning message. It tries to format the message reasonably as
required by RFC 3461 by adding a space after each newline

it uses the same logic as print_address_error() above. if af_pass_message is true
and addr->message is set it uses the remote host answer. if not addr->user_message
is used instead if available.

Arguments:
  addr         the address
  f            the FILE to print on

Returns:       nothing
*/

static void
print_dsn_diagnostic_code(const address_item *addr, FILE *f)
{
uschar *s = testflag(addr, af_pass_message) ? addr->message : NULL;

/* af_pass_message and addr->message set ? print remote host answer */
if (s)
  {
  DEBUG(D_deliver)
    debug_printf("DSN Diagnostic-Code: addr->message = %s\n", addr->message);

  /* search first ": ". we assume to find the remote-MTA answer there */
  if (!(s = Ustrstr(addr->message, ": ")))
    return;				/* not found, bail out */
  s += 2;  /* skip ": " */
  fprintf(f, "Diagnostic-Code: smtp; ");
  }
/* no message available. do nothing */
else return;

while (*s)
  if (*s == '\\' && s[1] == 'n')
    {
    fputs("\n ", f);    /* as defined in RFC 3461 */
    s += 2;
    }
  else
    fputc(*s++, f);

fputc('\n', f);
}


/*************************************************
*     Check list of addresses for duplication    *
*************************************************/

/* This function was introduced when the test for duplicate addresses that are
not pipes, files, or autoreplies was moved from the middle of routing to when
routing was complete. That was to fix obscure cases when the routing history
affects the subsequent routing of identical addresses. This function is called
after routing, to check that the final routed addresses are not duplicates.

If we detect a duplicate, we remember what it is a duplicate of. Note that
pipe, file, and autoreply de-duplication is handled during routing, so we must
leave such "addresses" alone here, as otherwise they will incorrectly be
discarded.

Argument:     address of list anchor
Returns:      nothing
*/

static void
do_duplicate_check(address_item **anchor)
{
address_item *addr;
while ((addr = *anchor) != NULL)
  {
  tree_node *tnode;
  if (testflag(addr, af_pfr))
    {
    anchor = &(addr->next);
    }
  else if ((tnode = tree_search(tree_duplicates, addr->unique)) != NULL)
    {
    DEBUG(D_deliver|D_route)
      debug_printf("%s is a duplicate address: discarded\n", addr->unique);
    *anchor = addr->next;
    addr->dupof = tnode->data.ptr;
    addr->next = addr_duplicate;
    addr_duplicate = addr;
    }
  else
    {
    tree_add_duplicate(addr->unique, addr);
    anchor = &(addr->next);
    }
  }
}




/*************************************************
*              Deliver one message               *
*************************************************/

/* This is the function which is called when a message is to be delivered. It
is passed the id of the message. It is possible that the message no longer
exists, if some other process has delivered it, and it is also possible that
the message is being worked on by another process, in which case the data file
will be locked.

If no delivery is attempted for any of the above reasons, the function returns
DELIVER_NOT_ATTEMPTED.

If the give_up flag is set true, do not attempt any deliveries, but instead
fail all outstanding addresses and return the message to the sender (or
whoever).

A delivery operation has a process all to itself; we never deliver more than
one message in the same process. Therefore we needn't worry too much about
store leakage.

Arguments:
  id          the id of the message to be delivered
  forced      TRUE if delivery was forced by an administrator; this overrides
              retry delays and causes a delivery to be tried regardless
  give_up     TRUE if an administrator has requested that delivery attempts
              be abandoned

Returns:      When the global variable mua_wrapper is FALSE:
                DELIVER_ATTEMPTED_NORMAL   if a delivery attempt was made
                DELIVER_NOT_ATTEMPTED      otherwise (see comment above)
              When the global variable mua_wrapper is TRUE:
                DELIVER_MUA_SUCCEEDED      if delivery succeeded
                DELIVER_MUA_FAILED         if delivery failed
                DELIVER_NOT_ATTEMPTED      if not attempted (should not occur)
*/

int
deliver_message(uschar *id, BOOL forced, BOOL give_up)
{
int i, rc;
int final_yield = DELIVER_ATTEMPTED_NORMAL;
time_t now = time(NULL);
address_item *addr_last = NULL;
uschar *filter_message = NULL;
FILE *jread;
int process_recipients = RECIP_ACCEPT;
open_db dbblock;
open_db *dbm_file;
extern int acl_where;

uschar *info = (queue_run_pid == (pid_t)0)?
  string_sprintf("delivering %s", id) :
  string_sprintf("delivering %s (queue run pid %d)", id, queue_run_pid);

/* If the D_process_info bit is on, set_process_info() will output debugging
information. If not, we want to show this initial information if D_deliver or
D_queue_run is set or in verbose mode. */

set_process_info("%s", info);

if ((debug_selector & D_process_info) == 0 &&
    (debug_selector & (D_deliver|D_queue_run|D_v)) != 0)
  debug_printf("%s\n", info);

/* Ensure that we catch any subprocesses that are created. Although Exim
sets SIG_DFL as its initial default, some routes through the code end up
here with it set to SIG_IGN - cases where a non-synchronous delivery process
has been forked, but no re-exec has been done. We use sigaction rather than
plain signal() on those OS where SA_NOCLDWAIT exists, because we want to be
sure it is turned off. (There was a problem on AIX with this.) */

#ifdef SA_NOCLDWAIT
  {
  struct sigaction act;
  act.sa_handler = SIG_DFL;
  sigemptyset(&(act.sa_mask));
  act.sa_flags = 0;
  sigaction(SIGCHLD, &act, NULL);
  }
#else
signal(SIGCHLD, SIG_DFL);
#endif

/* Make the forcing flag available for routers and transports, set up the
global message id field, and initialize the count for returned files and the
message size. This use of strcpy() is OK because the length id is checked when
it is obtained from a command line (the -M or -q options), and otherwise it is
known to be a valid message id. */

Ustrcpy(message_id, id);
deliver_force = forced;
return_count = 0;
message_size = 0;

/* Initialize some flags */

update_spool = FALSE;
remove_journal = TRUE;

/* Set a known context for any ACLs we call via expansions */
acl_where = ACL_WHERE_DELIVERY;

/* Reset the random number generator, so that if several delivery processes are
started from a queue runner that has already used random numbers (for sorting),
they don't all get the same sequence. */

random_seed = 0;

/* Open and lock the message's data file. Exim locks on this one because the
header file may get replaced as it is re-written during the delivery process.
Any failures cause messages to be written to the log, except for missing files
while queue running - another process probably completed delivery. As part of
opening the data file, message_subdir gets set. */

if (!spool_open_datafile(id))
  return continue_closedown();  /* yields DELIVER_NOT_ATTEMPTED */

/* The value of message_size at this point has been set to the data length,
plus one for the blank line that notionally precedes the data. */

/* Now read the contents of the header file, which will set up the headers in
store, and also the list of recipients and the tree of non-recipients and
assorted flags. It updates message_size. If there is a reading or format error,
give up; if the message has been around for sufficiently long, remove it. */

sprintf(CS spoolname, "%s-H", id);
if ((rc = spool_read_header(spoolname, TRUE, TRUE)) != spool_read_OK)
  {
  if (errno == ERRNO_SPOOLFORMAT)
    {
    struct stat statbuf;
    sprintf(CS big_buffer, "%s/input/%s/%s", spool_directory, message_subdir,
      spoolname);
    if (Ustat(big_buffer, &statbuf) == 0)
      log_write(0, LOG_MAIN, "Format error in spool file %s: "
        "size=" OFF_T_FMT, spoolname, statbuf.st_size);
    else log_write(0, LOG_MAIN, "Format error in spool file %s", spoolname);
    }
  else
    log_write(0, LOG_MAIN, "Error reading spool file %s: %s", spoolname,
      strerror(errno));

  /* If we managed to read the envelope data, received_time contains the
  time the message was received. Otherwise, we can calculate it from the
  message id. */

  if (rc != spool_read_hdrerror)
    {
    received_time = 0;
    for (i = 0; i < 6; i++)
      received_time = received_time * BASE_62 + tab62[id[i] - '0'];
    }

  /* If we've had this malformed message too long, sling it. */

  if (now - received_time > keep_malformed)
    {
    sprintf(CS spoolname, "%s/msglog/%s/%s", spool_directory, message_subdir, id);
    Uunlink(spoolname);
    sprintf(CS spoolname, "%s/input/%s/%s-D", spool_directory, message_subdir, id);
    Uunlink(spoolname);
    sprintf(CS spoolname, "%s/input/%s/%s-H", spool_directory, message_subdir, id);
    Uunlink(spoolname);
    sprintf(CS spoolname, "%s/input/%s/%s-J", spool_directory, message_subdir, id);
    Uunlink(spoolname);
    log_write(0, LOG_MAIN, "Message removed because older than %s",
      readconf_printtime(keep_malformed));
    }

  (void)close(deliver_datafile);
  deliver_datafile = -1;
  return continue_closedown();   /* yields DELIVER_NOT_ATTEMPTED */
  }

/* The spool header file has been read. Look to see if there is an existing
journal file for this message. If there is, it means that a previous delivery
attempt crashed (program or host) before it could update the spool header file.
Read the list of delivered addresses from the journal and add them to the
nonrecipients tree. Then update the spool file. We can leave the journal in
existence, as it will get further successful deliveries added to it in this
run, and it will be deleted if this function gets to its end successfully.
Otherwise it might be needed again. */

sprintf(CS spoolname, "%s/input/%s/%s-J", spool_directory, message_subdir, id);
jread = Ufopen(spoolname, "rb");
if (jread != NULL)
  {
  while (Ufgets(big_buffer, big_buffer_size, jread) != NULL)
    {
    int n = Ustrlen(big_buffer);
    big_buffer[n-1] = 0;
    tree_add_nonrecipient(big_buffer);
    DEBUG(D_deliver) debug_printf("Previously delivered address %s taken from "
      "journal file\n", big_buffer);
    }
  (void)fclose(jread);
  /* Panic-dies on error */
  (void)spool_write_header(message_id, SW_DELIVERING, NULL);
  }
else if (errno != ENOENT)
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "attempt to open journal for reading gave: "
    "%s", strerror(errno));
  return continue_closedown();   /* yields DELIVER_NOT_ATTEMPTED */
  }

/* A null recipients list indicates some kind of disaster. */

if (recipients_list == NULL)
  {
  (void)close(deliver_datafile);
  deliver_datafile = -1;
  log_write(0, LOG_MAIN, "Spool error: no recipients for %s", spoolname);
  return continue_closedown();   /* yields DELIVER_NOT_ATTEMPTED */
  }


/* Handle a message that is frozen. There are a number of different things that
can happen, but in the default situation, unless forced, no delivery is
attempted. */

if (deliver_freeze)
  {
#ifdef SUPPORT_MOVE_FROZEN_MESSAGES
  /* Moving to another directory removes the message from Exim's view. Other
  tools must be used to deal with it. Logging of this action happens in
  spool_move_message() and its subfunctions. */

  if (move_frozen_messages &&
      spool_move_message(id, message_subdir, US"", US"F"))
    return continue_closedown();   /* yields DELIVER_NOT_ATTEMPTED */
#endif

  /* For all frozen messages (bounces or not), timeout_frozen_after sets the
  maximum time to keep messages that are frozen. Thaw if we reach it, with a
  flag causing all recipients to be failed. The time is the age of the
  message, not the time since freezing. */

  if (timeout_frozen_after > 0 && message_age >= timeout_frozen_after)
    {
    log_write(0, LOG_MAIN, "cancelled by timeout_frozen_after");
    process_recipients = RECIP_FAIL_TIMEOUT;
    }

  /* For bounce messages (and others with no sender), thaw if the error message
  ignore timer is exceeded. The message will be discarded if this delivery
  fails. */

  else if (sender_address[0] == 0 && message_age >= ignore_bounce_errors_after)
    {
    log_write(0, LOG_MAIN, "Unfrozen by errmsg timer");
    }

  /* If this is a bounce message, or there's no auto thaw, or we haven't
  reached the auto thaw time yet, and this delivery is not forced by an admin
  user, do not attempt delivery of this message. Note that forced is set for
  continuing messages down the same channel, in order to skip load checking and
  ignore hold domains, but we don't want unfreezing in that case. */

  else
    {
    if ((sender_address[0] == 0 ||
         auto_thaw <= 0 ||
         now <= deliver_frozen_at + auto_thaw
        )
        &&
        (!forced || !deliver_force_thaw || !admin_user ||
          continue_hostname != NULL
        ))
      {
      (void)close(deliver_datafile);
      deliver_datafile = -1;
      log_write(L_skip_delivery, LOG_MAIN, "Message is frozen");
      return continue_closedown();   /* yields DELIVER_NOT_ATTEMPTED */
      }

    /* If delivery was forced (by an admin user), assume a manual thaw.
    Otherwise it's an auto thaw. */

    if (forced)
      {
      deliver_manual_thaw = TRUE;
      log_write(0, LOG_MAIN, "Unfrozen by forced delivery");
      }
    else log_write(0, LOG_MAIN, "Unfrozen by auto-thaw");
    }

  /* We get here if any of the rules for unfreezing have triggered. */

  deliver_freeze = FALSE;
  update_spool = TRUE;
  }


/* Open the message log file if we are using them. This records details of
deliveries, deferments, and failures for the benefit of the mail administrator.
The log is not used by exim itself to track the progress of a message; that is
done by rewriting the header spool file. */

if (message_logs)
  {
  uschar *error;
  int fd;

  sprintf(CS spoolname, "%s/msglog/%s/%s", spool_directory, message_subdir, id);
  fd = open_msglog_file(spoolname, SPOOL_MODE, &error);

  if (fd < 0)
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "Couldn't %s message log %s: %s", error,
      spoolname, strerror(errno));
    return continue_closedown();   /* yields DELIVER_NOT_ATTEMPTED */
    }

  /* Make a C stream out of it. */

  message_log = fdopen(fd, "a");
  if (message_log == NULL)
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "Couldn't fdopen message log %s: %s",
      spoolname, strerror(errno));
    return continue_closedown();   /* yields DELIVER_NOT_ATTEMPTED */
    }
  }


/* If asked to give up on a message, log who did it, and set the action for all
the addresses. */

if (give_up)
  {
  struct passwd *pw = getpwuid(real_uid);
  log_write(0, LOG_MAIN, "cancelled by %s", (pw != NULL)?
        US pw->pw_name : string_sprintf("uid %ld", (long int)real_uid));
  process_recipients = RECIP_FAIL;
  }

/* Otherwise, if there are too many Received: headers, fail all recipients. */

else if (received_count > received_headers_max)
  process_recipients = RECIP_FAIL_LOOP;

/* Otherwise, if a system-wide, address-independent message filter is
specified, run it now, except in the case when we are failing all recipients as
a result of timeout_frozen_after. If the system filter yields "delivered", then
ignore the true recipients of the message. Failure of the filter file is
logged, and the delivery attempt fails. */

else if (system_filter != NULL && process_recipients != RECIP_FAIL_TIMEOUT)
  {
  int rc;
  int filtertype;
  ugid_block ugid;
  redirect_block redirect;

  if (system_filter_uid_set)
    {
    ugid.uid = system_filter_uid;
    ugid.gid = system_filter_gid;
    ugid.uid_set = ugid.gid_set = TRUE;
    }
  else
    {
    ugid.uid_set = ugid.gid_set = FALSE;
    }

  return_path = sender_address;
  enable_dollar_recipients = TRUE;   /* Permit $recipients in system filter */
  system_filtering = TRUE;

  /* Any error in the filter file causes a delivery to be abandoned. */

  redirect.string = system_filter;
  redirect.isfile = TRUE;
  redirect.check_owner = redirect.check_group = FALSE;
  redirect.owners = NULL;
  redirect.owngroups = NULL;
  redirect.pw = NULL;
  redirect.modemask = 0;

  DEBUG(D_deliver|D_filter) debug_printf("running system filter\n");

  rc = rda_interpret(
    &redirect,              /* Where the data is */
    RDO_DEFER |             /* Turn on all the enabling options */
      RDO_FAIL |            /* Leave off all the disabling options */
      RDO_FILTER |
      RDO_FREEZE |
      RDO_REALLOG |
      RDO_REWRITE,
    NULL,                   /* No :include: restriction (not used in filter) */
    NULL,                   /* No sieve vacation directory (not sieve!) */
    NULL,                   /* No sieve enotify mailto owner (not sieve!) */
    NULL,                   /* No sieve user address (not sieve!) */
    NULL,                   /* No sieve subaddress (not sieve!) */
    &ugid,                  /* uid/gid data */
    &addr_new,              /* Where to hang generated addresses */
    &filter_message,        /* Where to put error message */
    NULL,                   /* Don't skip syntax errors */
    &filtertype,            /* Will always be set to FILTER_EXIM for this call */
    US"system filter");     /* For error messages */

  DEBUG(D_deliver|D_filter) debug_printf("system filter returned %d\n", rc);

  if (rc == FF_ERROR || rc == FF_NONEXIST)
    {
    (void)close(deliver_datafile);
    deliver_datafile = -1;
    log_write(0, LOG_MAIN|LOG_PANIC, "Error in system filter: %s",
      string_printing(filter_message));
    return continue_closedown();   /* yields DELIVER_NOT_ATTEMPTED */
    }

  /* Reset things. If the filter message is an empty string, which can happen
  for a filter "fail" or "freeze" command with no text, reset it to NULL. */

  system_filtering = FALSE;
  enable_dollar_recipients = FALSE;
  if (filter_message != NULL && filter_message[0] == 0) filter_message = NULL;

  /* Save the values of the system filter variables so that user filters
  can use them. */

  memcpy(filter_sn, filter_n, sizeof(filter_sn));

  /* The filter can request that delivery of the original addresses be
  deferred. */

  if (rc == FF_DEFER)
    {
    process_recipients = RECIP_DEFER;
    deliver_msglog("Delivery deferred by system filter\n");
    log_write(0, LOG_MAIN, "Delivery deferred by system filter");
    }

  /* The filter can request that a message be frozen, but this does not
  take place if the message has been manually thawed. In that case, we must
  unset "delivered", which is forced by the "freeze" command to make -bF
  work properly. */

  else if (rc == FF_FREEZE && !deliver_manual_thaw)
    {
    deliver_freeze = TRUE;
    deliver_frozen_at = time(NULL);
    process_recipients = RECIP_DEFER;
    frozen_info = string_sprintf(" by the system filter%s%s",
      (filter_message == NULL)? US"" : US": ",
      (filter_message == NULL)? US"" : filter_message);
    }

  /* The filter can request that a message be failed. The error message may be
  quite long - it is sent back to the sender in the bounce - but we don't want
  to fill up the log with repetitions of it. If it starts with << then the text
  between << and >> is written to the log, with the rest left for the bounce
  message. */

  else if (rc == FF_FAIL)
    {
    uschar *colon = US"";
    uschar *logmsg = US"";
    int loglen = 0;

    process_recipients = RECIP_FAIL_FILTER;

    if (filter_message != NULL)
      {
      uschar *logend;
      colon = US": ";
      if (filter_message[0] == '<' && filter_message[1] == '<' &&
          (logend = Ustrstr(filter_message, ">>")) != NULL)
        {
        logmsg = filter_message + 2;
        loglen = logend - logmsg;
        filter_message = logend + 2;
        if (filter_message[0] == 0) filter_message = NULL;
        }
      else
        {
        logmsg = filter_message;
        loglen = Ustrlen(filter_message);
        }
      }

    log_write(0, LOG_MAIN, "cancelled by system filter%s%.*s", colon, loglen,
      logmsg);
    }

  /* Delivery can be restricted only to those recipients (if any) that the
  filter specified. */

  else if (rc == FF_DELIVERED)
    {
    process_recipients = RECIP_IGNORE;
    if (addr_new == NULL)
      log_write(0, LOG_MAIN, "=> discarded (system filter)");
    else
      log_write(0, LOG_MAIN, "original recipients ignored (system filter)");
    }

  /* If any new addresses were created by the filter, fake up a "parent"
  for them. This is necessary for pipes, etc., which are expected to have
  parents, and it also gives some sensible logging for others. Allow
  pipes, files, and autoreplies, and run them as the filter uid if set,
  otherwise as the current uid. */

  if (addr_new != NULL)
    {
    int uid = (system_filter_uid_set)? system_filter_uid : geteuid();
    int gid = (system_filter_gid_set)? system_filter_gid : getegid();

    /* The text "system-filter" is tested in transport_set_up_command() and in
    set_up_shell_command() in the pipe transport, to enable them to permit
    $recipients, so don't change it here without also changing it there. */

    address_item *p = addr_new;
    address_item *parent = deliver_make_addr(US"system-filter", FALSE);

    parent->domain = string_copylc(qualify_domain_recipient);
    parent->local_part = US"system-filter";

    /* As part of this loop, we arrange for addr_last to end up pointing
    at the final address. This is used if we go on to add addresses for the
    original recipients. */

    while (p != NULL)
      {
      if (parent->child_count == SHRT_MAX)
        log_write(0, LOG_MAIN|LOG_PANIC_DIE, "system filter generated more "
          "than %d delivery addresses", SHRT_MAX);
      parent->child_count++;
      p->parent = parent;

      if (testflag(p, af_pfr))
        {
        uschar *tpname;
        uschar *type;
        p->uid = uid;
        p->gid = gid;
        setflag(p, af_uid_set |
                   af_gid_set |
                   af_allow_file |
                   af_allow_pipe |
                   af_allow_reply);

        /* Find the name of the system filter's appropriate pfr transport */

        if (p->address[0] == '|')
          {
          type = US"pipe";
          tpname = system_filter_pipe_transport;
          address_pipe = p->address;
          }
        else if (p->address[0] == '>')
          {
          type = US"reply";
          tpname = system_filter_reply_transport;
          }
        else
          {
          if (p->address[Ustrlen(p->address)-1] == '/')
            {
            type = US"directory";
            tpname = system_filter_directory_transport;
            }
          else
            {
            type = US"file";
            tpname = system_filter_file_transport;
            }
          address_file = p->address;
          }

        /* Now find the actual transport, first expanding the name. We have
        set address_file or address_pipe above. */

        if (tpname != NULL)
          {
          uschar *tmp = expand_string(tpname);
          address_file = address_pipe = NULL;
          if (tmp == NULL)
            p->message = string_sprintf("failed to expand \"%s\" as a "
              "system filter transport name", tpname);
          tpname = tmp;
          }
        else
          {
          p->message = string_sprintf("system_filter_%s_transport is unset",
            type);
          }

        if (tpname != NULL)
          {
          transport_instance *tp;
          for (tp = transports; tp != NULL; tp = tp->next)
            {
            if (Ustrcmp(tp->name, tpname) == 0)
              {
              p->transport = tp;
              break;
              }
            }
          if (tp == NULL)
            p->message = string_sprintf("failed to find \"%s\" transport "
              "for system filter delivery", tpname);
          }

        /* If we couldn't set up a transport, defer the delivery, putting the
        error on the panic log as well as the main log. */

        if (p->transport == NULL)
          {
          address_item *badp = p;
          p = p->next;
          if (addr_last == NULL) addr_new = p; else addr_last->next = p;
          badp->local_part = badp->address;   /* Needed for log line */
          post_process_one(badp, DEFER, LOG_MAIN|LOG_PANIC, DTYPE_ROUTER, 0);
          continue;
          }
        }    /* End of pfr handling */

      /* Either a non-pfr delivery, or we found a transport */

      DEBUG(D_deliver|D_filter)
        debug_printf("system filter added %s\n", p->address);

      addr_last = p;
      p = p->next;
      }    /* Loop through all addr_new addresses */
    }
  }


/* Scan the recipients list, and for every one that is not in the non-
recipients tree, add an addr item to the chain of new addresses. If the pno
value is non-negative, we must set the onetime parent from it. This which
points to the relevant entry in the recipients list.

This processing can be altered by the setting of the process_recipients
variable, which is changed if recipients are to be ignored, failed, or
deferred. This can happen as a result of system filter activity, or if the -Mg
option is used to fail all of them.

Duplicate addresses are handled later by a different tree structure; we can't
just extend the non-recipients tree, because that will be re-written to the
spool if the message is deferred, and in any case there are casing
complications for local addresses. */

if (process_recipients != RECIP_IGNORE)
  {
  for (i = 0; i < recipients_count; i++)
    {
    if (tree_search(tree_nonrecipients, recipients_list[i].address) == NULL)
      {
      recipient_item *r = recipients_list + i;
      address_item *new = deliver_make_addr(r->address, FALSE);
      new->prop.errors_address = r->errors_to;
#ifdef EXPERIMENTAL_INTERNATIONAL
      if ((new->prop.utf8_msg = message_smtputf8))
	{
	new->prop.utf8_downcvt =       message_utf8_downconvert == 1;
	new->prop.utf8_downcvt_maybe = message_utf8_downconvert == -1;
	DEBUG(D_deliver) debug_printf("utf8, downconvert %s\n",
	  new->prop.utf8_downcvt ? "yes"
	  : new->prop.utf8_downcvt_maybe ? "ifneeded"
	  : "no");
	}
#endif

      if (r->pno >= 0)
        new->onetime_parent = recipients_list[r->pno].address;

      /* If DSN support is enabled, set the dsn flags and the original receipt 
         to be passed on to other DSN enabled MTAs */
      new->dsn_flags = r->dsn_flags & rf_dsnflags;
      new->dsn_orcpt = r->orcpt;
      DEBUG(D_deliver) debug_printf("DSN: set orcpt: %s  flags: %d\n",
	new->dsn_orcpt, new->dsn_flags);

      switch (process_recipients)
        {
        /* RECIP_DEFER is set when a system filter freezes a message. */

        case RECIP_DEFER:
        new->next = addr_defer;
        addr_defer = new;
        break;


        /* RECIP_FAIL_FILTER is set when a system filter has obeyed a "fail"
        command. */

        case RECIP_FAIL_FILTER:
        new->message =
          (filter_message == NULL)? US"delivery cancelled" : filter_message;
        setflag(new, af_pass_message);
        goto RECIP_QUEUE_FAILED;   /* below */


        /* RECIP_FAIL_TIMEOUT is set when a message is frozen, but is older
        than the value in timeout_frozen_after. Treat non-bounce messages
        similarly to -Mg; for bounce messages we just want to discard, so
        don't put the address on the failed list. The timeout has already
        been logged. */

        case RECIP_FAIL_TIMEOUT:
        new->message  = US"delivery cancelled; message timed out";
        goto RECIP_QUEUE_FAILED;   /* below */


        /* RECIP_FAIL is set when -Mg has been used. */

        case RECIP_FAIL:
        new->message  = US"delivery cancelled by administrator";
        /* Fall through */

        /* Common code for the failure cases above. If this is not a bounce
        message, put the address on the failed list so that it is used to
        create a bounce. Otherwise do nothing - this just discards the address.
        The incident has already been logged. */

        RECIP_QUEUE_FAILED:
        if (sender_address[0] != 0)
          {
          new->next = addr_failed;
          addr_failed = new;
          }
        break;


        /* RECIP_FAIL_LOOP is set when there are too many Received: headers
        in the message. Process each address as a routing failure; if this
        is a bounce message, it will get frozen. */

        case RECIP_FAIL_LOOP:
        new->message = US"Too many \"Received\" headers - suspected mail loop";
        post_process_one(new, FAIL, LOG_MAIN, DTYPE_ROUTER, 0);
        break;


        /* Value should be RECIP_ACCEPT; take this as the safe default. */

        default:
        if (addr_new == NULL) addr_new = new; else addr_last->next = new;
        addr_last = new;
        break;
        }

#ifdef EXPERIMENTAL_EVENT
      if (process_recipients != RECIP_ACCEPT)
	{
	uschar * save_local =  deliver_localpart;
	const uschar * save_domain = deliver_domain;

	deliver_localpart = expand_string(
		      string_sprintf("${local_part:%s}", new->address));
	deliver_domain =    expand_string(
		      string_sprintf("${domain:%s}", new->address));

	(void) event_raise(event_action,
		      US"msg:fail:internal", new->message);

	deliver_localpart = save_local;
	deliver_domain =    save_domain;
	}
#endif
      }
    }
  }

DEBUG(D_deliver)
  {
  address_item *p = addr_new;
  debug_printf("Delivery address list:\n");
  while (p != NULL)
    {
    debug_printf("  %s %s\n", p->address, (p->onetime_parent == NULL)? US"" :
      p->onetime_parent);
    p = p->next;
    }
  }

/* Set up the buffers used for copying over the file when delivering. */

deliver_in_buffer = store_malloc(DELIVER_IN_BUFFER_SIZE);
deliver_out_buffer = store_malloc(DELIVER_OUT_BUFFER_SIZE);



/* Until there are no more new addresses, handle each one as follows:

 . If this is a generated address (indicated by the presence of a parent
   pointer) then check to see whether it is a pipe, file, or autoreply, and
   if so, handle it directly here. The router that produced the address will
   have set the allow flags into the address, and also set the uid/gid required.
   Having the routers generate new addresses and then checking them here at
   the outer level is tidier than making each router do the checking, and
   means that routers don't need access to the failed address queue.

 . Break up the address into local part and domain, and make lowercased
   versions of these strings. We also make unquoted versions of the local part.

 . Handle the percent hack for those domains for which it is valid.

 . For child addresses, determine if any of the parents have the same address.
   If so, generate a different string for previous delivery checking. Without
   this code, if the address spqr generates spqr via a forward or alias file,
   delivery of the generated spqr stops further attempts at the top level spqr,
   which is not what is wanted - it may have generated other addresses.

 . Check on the retry database to see if routing was previously deferred, but
   only if in a queue run. Addresses that are to be routed are put on the
   addr_route chain. Addresses that are to be deferred are put on the
   addr_defer chain. We do all the checking first, so as not to keep the
   retry database open any longer than necessary.

 . Now we run the addresses through the routers. A router may put the address
   on either the addr_local or the addr_remote chain for local or remote
   delivery, respectively, or put it on the addr_failed chain if it is
   undeliveable, or it may generate child addresses and put them on the
   addr_new chain, or it may defer an address. All the chain anchors are
   passed as arguments so that the routers can be called for verification
   purposes as well.

 . If new addresses have been generated by the routers, da capo.
*/

header_rewritten = FALSE;          /* No headers rewritten yet */
while (addr_new != NULL)           /* Loop until all addresses dealt with */
  {
  address_item *addr, *parent;
  dbm_file = dbfn_open(US"retry", O_RDONLY, &dbblock, FALSE);

  /* Failure to open the retry database is treated the same as if it does
  not exist. In both cases, dbm_file is NULL. */

  if (dbm_file == NULL)
    {
    DEBUG(D_deliver|D_retry|D_route|D_hints_lookup)
      debug_printf("no retry data available\n");
    }

  /* Scan the current batch of new addresses, to handle pipes, files and
  autoreplies, and determine which others are ready for routing. */

  while (addr_new != NULL)
    {
    int rc;
    uschar *p;
    tree_node *tnode;
    dbdata_retry *domain_retry_record;
    dbdata_retry *address_retry_record;

    addr = addr_new;
    addr_new = addr->next;

    DEBUG(D_deliver|D_retry|D_route)
      {
      debug_printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
      debug_printf("Considering: %s\n", addr->address);
      }

    /* Handle generated address that is a pipe or a file or an autoreply. */

    if (testflag(addr, af_pfr))
      {
      /* If an autoreply in a filter could not generate a syntactically valid
      address, give up forthwith. Set af_ignore_error so that we don't try to
      generate a bounce. */

      if (testflag(addr, af_bad_reply))
        {
        addr->basic_errno = ERRNO_BADADDRESS2;
        addr->local_part = addr->address;
        addr->message =
          US"filter autoreply generated syntactically invalid recipient";
        setflag(addr, af_ignore_error);
        (void)post_process_one(addr, FAIL, LOG_MAIN, DTYPE_ROUTER, 0);
        continue;   /* with the next new address */
        }

      /* If two different users specify delivery to the same pipe or file or
      autoreply, there should be two different deliveries, so build a unique
      string that incorporates the original address, and use this for
      duplicate testing and recording delivery, and also for retrying. */

      addr->unique =
        string_sprintf("%s:%s", addr->address, addr->parent->unique +
          (testflag(addr->parent, af_homonym)? 3:0));

      addr->address_retry_key = addr->domain_retry_key =
        string_sprintf("T:%s", addr->unique);

      /* If a filter file specifies two deliveries to the same pipe or file,
      we want to de-duplicate, but this is probably not wanted for two mail
      commands to the same address, where probably both should be delivered.
      So, we have to invent a different unique string in that case. Just
      keep piling '>' characters on the front. */

      if (addr->address[0] == '>')
        {
        while (tree_search(tree_duplicates, addr->unique) != NULL)
          addr->unique = string_sprintf(">%s", addr->unique);
        }

      else if ((tnode = tree_search(tree_duplicates, addr->unique)) != NULL)
        {
        DEBUG(D_deliver|D_route)
          debug_printf("%s is a duplicate address: discarded\n", addr->address);
        addr->dupof = tnode->data.ptr;
        addr->next = addr_duplicate;
        addr_duplicate = addr;
        continue;
        }

      DEBUG(D_deliver|D_route) debug_printf("unique = %s\n", addr->unique);

      /* Check for previous delivery */

      if (tree_search(tree_nonrecipients, addr->unique) != NULL)
        {
        DEBUG(D_deliver|D_route)
          debug_printf("%s was previously delivered: discarded\n", addr->address);
        child_done(addr, tod_stamp(tod_log));
        continue;
        }

      /* Save for checking future duplicates */

      tree_add_duplicate(addr->unique, addr);

      /* Set local part and domain */

      addr->local_part = addr->address;
      addr->domain = addr->parent->domain;

      /* Ensure that the delivery is permitted. */

      if (testflag(addr, af_file))
        {
        if (!testflag(addr, af_allow_file))
          {
          addr->basic_errno = ERRNO_FORBIDFILE;
          addr->message = US"delivery to file forbidden";
          (void)post_process_one(addr, FAIL, LOG_MAIN, DTYPE_ROUTER, 0);
          continue;   /* with the next new address */
          }
        }
      else if (addr->address[0] == '|')
        {
        if (!testflag(addr, af_allow_pipe))
          {
          addr->basic_errno = ERRNO_FORBIDPIPE;
          addr->message = US"delivery to pipe forbidden";
          (void)post_process_one(addr, FAIL, LOG_MAIN, DTYPE_ROUTER, 0);
          continue;   /* with the next new address */
          }
        }
      else if (!testflag(addr, af_allow_reply))
        {
        addr->basic_errno = ERRNO_FORBIDREPLY;
        addr->message = US"autoreply forbidden";
        (void)post_process_one(addr, FAIL, LOG_MAIN, DTYPE_ROUTER, 0);
        continue;     /* with the next new address */
        }

      /* If the errno field is already set to BADTRANSPORT, it indicates
      failure to expand a transport string, or find the associated transport,
      or an unset transport when one is required. Leave this test till now so
      that the forbid errors are given in preference. */

      if (addr->basic_errno == ERRNO_BADTRANSPORT)
        {
        (void)post_process_one(addr, DEFER, LOG_MAIN, DTYPE_ROUTER, 0);
        continue;
        }

      /* Treat /dev/null as a special case and abandon the delivery. This
      avoids having to specify a uid on the transport just for this case.
      Arrange for the transport name to be logged as "**bypassed**". */

      if (Ustrcmp(addr->address, "/dev/null") == 0)
        {
        uschar *save = addr->transport->name;
        addr->transport->name = US"**bypassed**";
        (void)post_process_one(addr, OK, LOG_MAIN, DTYPE_TRANSPORT, '=');
        addr->transport->name = save;
        continue;   /* with the next new address */
        }

      /* Pipe, file, or autoreply delivery is to go ahead as a normal local
      delivery. */

      DEBUG(D_deliver|D_route)
        debug_printf("queued for %s transport\n", addr->transport->name);
      addr->next = addr_local;
      addr_local = addr;
      continue;       /* with the next new address */
      }

    /* Handle normal addresses. First, split up into local part and domain,
    handling the %-hack if necessary. There is the possibility of a defer from
    a lookup in percent_hack_domains. */

    if ((rc = deliver_split_address(addr)) == DEFER)
      {
      addr->message = US"cannot check percent_hack_domains";
      addr->basic_errno = ERRNO_LISTDEFER;
      (void)post_process_one(addr, DEFER, LOG_MAIN, DTYPE_NONE, 0);
      continue;
      }

    /* Check to see if the domain is held. If so, proceed only if the
    delivery was forced by hand. */

    deliver_domain = addr->domain;  /* set $domain */
    if (!forced && hold_domains != NULL &&
         (rc = match_isinlist(addr->domain, (const uschar **)&hold_domains, 0,
           &domainlist_anchor, addr->domain_cache, MCL_DOMAIN, TRUE,
           NULL)) != FAIL)
      {
      if (rc == DEFER)
        {
        addr->message = US"hold_domains lookup deferred";
        addr->basic_errno = ERRNO_LISTDEFER;
        }
      else
        {
        addr->message = US"domain is held";
        addr->basic_errno = ERRNO_HELD;
        }
      (void)post_process_one(addr, DEFER, LOG_MAIN, DTYPE_NONE, 0);
      continue;
      }

    /* Now we can check for duplicates and previously delivered addresses. In
    order to do this, we have to generate a "unique" value for each address,
    because there may be identical actual addresses in a line of descendents.
    The "unique" field is initialized to the same value as the "address" field,
    but gets changed here to cope with identically-named descendents. */

    for (parent = addr->parent; parent != NULL; parent = parent->parent)
      if (strcmpic(addr->address, parent->address) == 0) break;

    /* If there's an ancestor with the same name, set the homonym flag. This
    influences how deliveries are recorded. Then add a prefix on the front of
    the unique address. We use \n\ where n starts at 0 and increases each time.
    It is unlikely to pass 9, but if it does, it may look odd but will still
    work. This means that siblings or cousins with the same names are treated
    as duplicates, which is what we want. */

    if (parent != NULL)
      {
      setflag(addr, af_homonym);
      if (parent->unique[0] != '\\')
        addr->unique = string_sprintf("\\0\\%s", addr->address);
      else
        addr->unique = string_sprintf("\\%c\\%s", parent->unique[1] + 1,
          addr->address);
      }

    /* Ensure that the domain in the unique field is lower cased, because
    domains are always handled caselessly. */

    p = Ustrrchr(addr->unique, '@');
    while (*p != 0) { *p = tolower(*p); p++; }

    DEBUG(D_deliver|D_route) debug_printf("unique = %s\n", addr->unique);

    if (tree_search(tree_nonrecipients, addr->unique) != NULL)
      {
      DEBUG(D_deliver|D_route)
        debug_printf("%s was previously delivered: discarded\n", addr->unique);
      child_done(addr, tod_stamp(tod_log));
      continue;
      }

    /* Get the routing retry status, saving the two retry keys (with and
    without the local part) for subsequent use. If there is no retry record for
    the standard address routing retry key, we look for the same key with the
    sender attached, because this form is used by the smtp transport after a
    4xx response to RCPT when address_retry_include_sender is true. */

    addr->domain_retry_key = string_sprintf("R:%s", addr->domain);
    addr->address_retry_key = string_sprintf("R:%s@%s", addr->local_part,
      addr->domain);

    if (dbm_file == NULL)
      domain_retry_record = address_retry_record = NULL;
    else
      {
      domain_retry_record = dbfn_read(dbm_file, addr->domain_retry_key);
      if (domain_retry_record != NULL &&
          now - domain_retry_record->time_stamp > retry_data_expire)
        domain_retry_record = NULL;    /* Ignore if too old */

      address_retry_record = dbfn_read(dbm_file, addr->address_retry_key);
      if (address_retry_record != NULL &&
          now - address_retry_record->time_stamp > retry_data_expire)
        address_retry_record = NULL;   /* Ignore if too old */

      if (address_retry_record == NULL)
        {
        uschar *altkey = string_sprintf("%s:<%s>", addr->address_retry_key,
          sender_address);
        address_retry_record = dbfn_read(dbm_file, altkey);
        if (address_retry_record != NULL &&
            now - address_retry_record->time_stamp > retry_data_expire)
          address_retry_record = NULL;   /* Ignore if too old */
        }
      }

    DEBUG(D_deliver|D_retry)
      {
      if (domain_retry_record == NULL)
        debug_printf("no domain retry record\n");
      if (address_retry_record == NULL)
        debug_printf("no address retry record\n");
      }

    /* If we are sending a message down an existing SMTP connection, we must
    assume that the message which created the connection managed to route
    an address to that connection. We do not want to run the risk of taking
    a long time over routing here, because if we do, the server at the other
    end of the connection may time it out. This is especially true for messages
    with lots of addresses. For this kind of delivery, queue_running is not
    set, so we would normally route all addresses. We take a pragmatic approach
    and defer routing any addresses that have any kind of domain retry record.
    That is, we don't even look at their retry times. It doesn't matter if this
    doesn't work occasionally. This is all just an optimization, after all.

    The reason for not doing the same for address retries is that they normally
    arise from 4xx responses, not DNS timeouts. */

    if (continue_hostname != NULL && domain_retry_record != NULL)
      {
      addr->message = US"reusing SMTP connection skips previous routing defer";
      addr->basic_errno = ERRNO_RRETRY;
      (void)post_process_one(addr, DEFER, LOG_MAIN, DTYPE_ROUTER, 0);
      }

    /* If we are in a queue run, defer routing unless there is no retry data or
    we've passed the next retry time, or this message is forced. In other
    words, ignore retry data when not in a queue run.

    However, if the domain retry time has expired, always allow the routing
    attempt. If it fails again, the address will be failed. This ensures that
    each address is routed at least once, even after long-term routing
    failures.

    If there is an address retry, check that too; just wait for the next
    retry time. This helps with the case when the temporary error on the
    address was really message-specific rather than address specific, since
    it allows other messages through.

    We also wait for the next retry time if this is a message sent down an
    existing SMTP connection (even though that will be forced). Otherwise there
    will be far too many attempts for an address that gets a 4xx error. In
    fact, after such an error, we should not get here because, the host should
    not be remembered as one this message needs. However, there was a bug that
    used to cause this to  happen, so it is best to be on the safe side.

    Even if we haven't reached the retry time in the hints, there is one more
    check to do, which is for the ultimate address timeout. We only do this
    check if there is an address retry record and there is not a domain retry
    record; this implies that previous attempts to handle the address had the
    retry_use_local_parts option turned on. We use this as an approximation
    for the destination being like a local delivery, for example delivery over
    LMTP to an IMAP message store. In this situation users are liable to bump
    into their quota and thereby have intermittently successful deliveries,
    which keep the retry record fresh, which can lead to us perpetually
    deferring messages. */

    else if (((queue_running && !deliver_force) || continue_hostname != NULL)
            &&
            ((domain_retry_record != NULL &&
              now < domain_retry_record->next_try &&
              !domain_retry_record->expired)
            ||
            (address_retry_record != NULL &&
              now < address_retry_record->next_try))
            &&
	    (domain_retry_record != NULL ||
	     address_retry_record == NULL ||
	     !retry_ultimate_address_timeout(addr->address_retry_key,
	       addr->domain, address_retry_record, now)))
      {
      addr->message = US"retry time not reached";
      addr->basic_errno = ERRNO_RRETRY;
      (void)post_process_one(addr, DEFER, LOG_MAIN, DTYPE_ROUTER, 0);
      }

    /* The domain is OK for routing. Remember if retry data exists so it
    can be cleaned up after a successful delivery. */

    else
      {
      if (domain_retry_record != NULL || address_retry_record != NULL)
        setflag(addr, af_dr_retry_exists);
      addr->next = addr_route;
      addr_route = addr;
      DEBUG(D_deliver|D_route)
        debug_printf("%s: queued for routing\n", addr->address);
      }
    }

  /* The database is closed while routing is actually happening. Requests to
  update it are put on a chain and all processed together at the end. */

  if (dbm_file != NULL) dbfn_close(dbm_file);

  /* If queue_domains is set, we don't even want to try routing addresses in
  those domains. During queue runs, queue_domains is forced to be unset.
  Optimize by skipping this pass through the addresses if nothing is set. */

  if (!deliver_force && queue_domains != NULL)
    {
    address_item *okaddr = NULL;
    while (addr_route != NULL)
      {
      address_item *addr = addr_route;
      addr_route = addr->next;

      deliver_domain = addr->domain;  /* set $domain */
      if ((rc = match_isinlist(addr->domain, (const uschar **)&queue_domains, 0,
            &domainlist_anchor, addr->domain_cache, MCL_DOMAIN, TRUE, NULL))
              != OK)
        {
        if (rc == DEFER)
          {
          addr->basic_errno = ERRNO_LISTDEFER;
          addr->message = US"queue_domains lookup deferred";
          (void)post_process_one(addr, DEFER, LOG_MAIN, DTYPE_ROUTER, 0);
          }
        else
          {
          addr->next = okaddr;
          okaddr = addr;
          }
        }
      else
        {
        addr->basic_errno = ERRNO_QUEUE_DOMAIN;
        addr->message = US"domain is in queue_domains";
        (void)post_process_one(addr, DEFER, LOG_MAIN, DTYPE_ROUTER, 0);
        }
      }

    addr_route = okaddr;
    }

  /* Now route those addresses that are not deferred. */

  while (addr_route != NULL)
    {
    int rc;
    address_item *addr = addr_route;
    const uschar *old_domain = addr->domain;
    uschar *old_unique = addr->unique;
    addr_route = addr->next;
    addr->next = NULL;

    /* Just in case some router parameter refers to it. */

    return_path = (addr->prop.errors_address != NULL)?
      addr->prop.errors_address : sender_address;

    /* If a router defers an address, add a retry item. Whether or not to
    use the local part in the key is a property of the router. */

    if ((rc = route_address(addr, &addr_local, &addr_remote, &addr_new,
         &addr_succeed, v_none)) == DEFER)
      retry_add_item(addr, (addr->router->retry_use_local_part)?
        string_sprintf("R:%s@%s", addr->local_part, addr->domain) :
        string_sprintf("R:%s", addr->domain), 0);

    /* Otherwise, if there is an existing retry record in the database, add
    retry items to delete both forms. We must also allow for the possibility
    of a routing retry that includes the sender address. Since the domain might
    have been rewritten (expanded to fully qualified) as a result of routing,
    ensure that the rewritten form is also deleted. */

    else if (testflag(addr, af_dr_retry_exists))
      {
      uschar *altkey = string_sprintf("%s:<%s>", addr->address_retry_key,
        sender_address);
      retry_add_item(addr, altkey, rf_delete);
      retry_add_item(addr, addr->address_retry_key, rf_delete);
      retry_add_item(addr, addr->domain_retry_key, rf_delete);
      if (Ustrcmp(addr->domain, old_domain) != 0)
        retry_add_item(addr, string_sprintf("R:%s", old_domain), rf_delete);
      }

    /* DISCARD is given for :blackhole: and "seen finish". The event has been
    logged, but we need to ensure the address (and maybe parents) is marked
    done. */

    if (rc == DISCARD)
      {
      address_done(addr, tod_stamp(tod_log));
      continue;  /* route next address */
      }

    /* The address is finished with (failed or deferred). */

    if (rc != OK)
      {
      (void)post_process_one(addr, rc, LOG_MAIN, DTYPE_ROUTER, 0);
      continue;  /* route next address */
      }

    /* The address has been routed. If the router changed the domain, it will
    also have changed the unique address. We have to test whether this address
    has already been delivered, because it's the unique address that finally
    gets recorded. */

    if (addr->unique != old_unique &&
        tree_search(tree_nonrecipients, addr->unique) != 0)
      {
      DEBUG(D_deliver|D_route) debug_printf("%s was previously delivered: "
        "discarded\n", addr->address);
      if (addr_remote == addr) addr_remote = addr->next;
      else if (addr_local == addr) addr_local = addr->next;
      }

    /* If the router has same_domain_copy_routing set, we are permitted to copy
    the routing for any other addresses with the same domain. This is an
    optimisation to save repeated DNS lookups for "standard" remote domain
    routing. The option is settable only on routers that generate host lists.
    We play it very safe, and do the optimization only if the address is routed
    to a remote transport, there are no header changes, and the domain was not
    modified by the router. */

    if (addr_remote == addr &&
        addr->router->same_domain_copy_routing &&
        addr->prop.extra_headers == NULL &&
        addr->prop.remove_headers == NULL &&
        old_domain == addr->domain)
      {
      address_item **chain = &addr_route;
      while (*chain != NULL)
        {
        address_item *addr2 = *chain;
        if (Ustrcmp(addr2->domain, addr->domain) != 0)
          {
          chain = &(addr2->next);
          continue;
          }

        /* Found a suitable address; take it off the routing list and add it to
        the remote delivery list. */

        *chain = addr2->next;
        addr2->next = addr_remote;
        addr_remote = addr2;

        /* Copy the routing data */

        addr2->domain = addr->domain;
        addr2->router = addr->router;
        addr2->transport = addr->transport;
        addr2->host_list = addr->host_list;
        addr2->fallback_hosts = addr->fallback_hosts;
        addr2->prop.errors_address = addr->prop.errors_address;
        copyflag(addr2, addr, af_hide_child | af_local_host_removed);

        DEBUG(D_deliver|D_route)
          {
          debug_printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n"
                       "routing %s\n"
                       "Routing for %s copied from %s\n",
            addr2->address, addr2->address, addr->address);
          }
        }
      }
    }  /* Continue with routing the next address. */
  }    /* Loop to process any child addresses that the routers created, and
          any rerouted addresses that got put back on the new chain. */


/* Debugging: show the results of the routing */

DEBUG(D_deliver|D_retry|D_route)
  {
  address_item *p = addr_local;
  debug_printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
  debug_printf("After routing:\n  Local deliveries:\n");
  while (p != NULL)
    {
    debug_printf("    %s\n", p->address);
    p = p->next;
    }

  p = addr_remote;
  debug_printf("  Remote deliveries:\n");
  while (p != NULL)
    {
    debug_printf("    %s\n", p->address);
    p = p->next;
    }

  p = addr_failed;
  debug_printf("  Failed addresses:\n");
  while (p != NULL)
    {
    debug_printf("    %s\n", p->address);
    p = p->next;
    }

  p = addr_defer;
  debug_printf("  Deferred addresses:\n");
  while (p != NULL)
    {
    debug_printf("    %s\n", p->address);
    p = p->next;
    }
  }

/* Free any resources that were cached during routing. */

search_tidyup();
route_tidyup();

/* These two variables are set only during routing, after check_local_user.
Ensure they are not set in transports. */

local_user_gid = (gid_t)(-1);
local_user_uid = (uid_t)(-1);

/* Check for any duplicate addresses. This check is delayed until after
routing, because the flexibility of the routing configuration means that
identical addresses with different parentage may end up being redirected to
different addresses. Checking for duplicates too early (as we previously used
to) makes this kind of thing not work. */

do_duplicate_check(&addr_local);
do_duplicate_check(&addr_remote);

/* When acting as an MUA wrapper, we proceed only if all addresses route to a
remote transport. The check that they all end up in one transaction happens in
the do_remote_deliveries() function. */

if (mua_wrapper && (addr_local != NULL || addr_failed != NULL ||
                    addr_defer != NULL))
  {
  address_item *addr;
  uschar *which, *colon, *msg;

  if (addr_local != NULL)
    {
    addr = addr_local;
    which = US"local";
    }
  else if (addr_defer != NULL)
    {
    addr = addr_defer;
    which = US"deferred";
    }
  else
    {
    addr = addr_failed;
    which = US"failed";
    }

  while (addr->parent != NULL) addr = addr->parent;

  if (addr->message != NULL)
    {
    colon = US": ";
    msg = addr->message;
    }
  else colon = msg = US"";

  /* We don't need to log here for a forced failure as it will already
  have been logged. Defer will also have been logged, but as a defer, so we do
  need to do the failure logging. */

  if (addr != addr_failed)
    log_write(0, LOG_MAIN, "** %s routing yielded a %s delivery",
      addr->address, which);

  /* Always write an error to the caller */

  fprintf(stderr, "routing %s yielded a %s delivery%s%s\n", addr->address,
    which, colon, msg);

  final_yield = DELIVER_MUA_FAILED;
  addr_failed = addr_defer = NULL;   /* So that we remove the message */
  goto DELIVERY_TIDYUP;
  }


/* If this is a run to continue deliveries to an external channel that is
already set up, defer any local deliveries. */

if (continue_transport != NULL)
  {
  if (addr_defer == NULL) addr_defer = addr_local; else
    {
    address_item *addr = addr_defer;
    while (addr->next != NULL) addr = addr->next;
    addr->next = addr_local;
    }
  addr_local = NULL;
  }


/* Because address rewriting can happen in the routers, we should not really do
ANY deliveries until all addresses have been routed, so that all recipients of
the message get the same headers. However, this is in practice not always
possible, since sometimes remote addresses give DNS timeouts for days on end.
The pragmatic approach is to deliver what we can now, saving any rewritten
headers so that at least the next lot of recipients benefit from the rewriting
that has already been done.

If any headers have been rewritten during routing, update the spool file to
remember them for all subsequent deliveries. This can be delayed till later if
there is only address to be delivered - if it succeeds the spool write need not
happen. */

if (header_rewritten &&
    ((addr_local != NULL &&
       (addr_local->next != NULL || addr_remote != NULL)) ||
     (addr_remote != NULL && addr_remote->next != NULL)))
  {
  /* Panic-dies on error */
  (void)spool_write_header(message_id, SW_DELIVERING, NULL);
  header_rewritten = FALSE;
  }


/* If there are any deliveries to be done, open the journal file. This is used
to record successful deliveries as soon as possible after each delivery is
known to be complete. A file opened with O_APPEND is used so that several
processes can run simultaneously.

The journal is just insurance against crashes. When the spool file is
ultimately updated at the end of processing, the journal is deleted. If a
journal is found to exist at the start of delivery, the addresses listed
therein are added to the non-recipients. */

if (addr_local != NULL || addr_remote != NULL)
  {
  sprintf(CS spoolname, "%s/input/%s/%s-J", spool_directory, message_subdir, id);
  journal_fd = Uopen(spoolname, O_WRONLY|O_APPEND|O_CREAT, SPOOL_MODE);

  if (journal_fd < 0)
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "Couldn't open journal file %s: %s",
      spoolname, strerror(errno));
    return DELIVER_NOT_ATTEMPTED;
    }

  /* Set the close-on-exec flag, make the file owned by Exim, and ensure
  that the mode is correct - the group setting doesn't always seem to get
  set automatically. */

  if(  fcntl(journal_fd, F_SETFD, fcntl(journal_fd, F_GETFD) | FD_CLOEXEC)
    || fchown(journal_fd, exim_uid, exim_gid)
    || fchmod(journal_fd, SPOOL_MODE)
    )
    {
    int ret = Uunlink(spoolname);
    log_write(0, LOG_MAIN|LOG_PANIC, "Couldn't set perms on journal file %s: %s",
      spoolname, strerror(errno));
    if(ret  &&  errno != ENOENT)
      log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to unlink %s: %s",
        spoolname, strerror(errno));
    return DELIVER_NOT_ATTEMPTED;
    }
  }



/* Now we can get down to the business of actually doing deliveries. Local
deliveries are done first, then remote ones. If ever the problems of how to
handle fallback transports are figured out, this section can be put into a loop
for handling fallbacks, though the uid switching will have to be revised. */

/* Precompile a regex that is used to recognize a parameter in response
to an LHLO command, if is isn't already compiled. This may be used on both
local and remote LMTP deliveries. */

if (regex_IGNOREQUOTA == NULL) regex_IGNOREQUOTA =
  regex_must_compile(US"\\n250[\\s\\-]IGNOREQUOTA(\\s|\\n|$)", FALSE, TRUE);

/* Handle local deliveries */

if (addr_local != NULL)
  {
  DEBUG(D_deliver|D_transport)
    debug_printf(">>>>>>>>>>>>>>>> Local deliveries >>>>>>>>>>>>>>>>\n");
  do_local_deliveries();
  disable_logging = FALSE;
  }

/* If queue_run_local is set, we do not want to attempt any remote deliveries,
so just queue them all. */

if (queue_run_local)
  {
  while (addr_remote != NULL)
    {
    address_item *addr = addr_remote;
    addr_remote = addr->next;
    addr->next = NULL;
    addr->basic_errno = ERRNO_LOCAL_ONLY;
    addr->message = US"remote deliveries suppressed";
    (void)post_process_one(addr, DEFER, LOG_MAIN, DTYPE_TRANSPORT, 0);
    }
  }

/* Handle remote deliveries */

if (addr_remote != NULL)
  {
  DEBUG(D_deliver|D_transport)
    debug_printf(">>>>>>>>>>>>>>>> Remote deliveries >>>>>>>>>>>>>>>>\n");

  /* Precompile some regex that are used to recognize parameters in response
  to an EHLO command, if they aren't already compiled. */

  deliver_init();

  /* Now sort the addresses if required, and do the deliveries. The yield of
  do_remote_deliveries is FALSE when mua_wrapper is set and all addresses
  cannot be delivered in one transaction. */

  if (remote_sort_domains != NULL) sort_remote_deliveries();
  if (!do_remote_deliveries(FALSE))
    {
    log_write(0, LOG_MAIN, "** mua_wrapper is set but recipients cannot all "
      "be delivered in one transaction");
    fprintf(stderr, "delivery to smarthost failed (configuration problem)\n");

    final_yield = DELIVER_MUA_FAILED;
    addr_failed = addr_defer = NULL;   /* So that we remove the message */
    goto DELIVERY_TIDYUP;
    }

  /* See if any of the addresses that failed got put on the queue for delivery
  to their fallback hosts. We do it this way because often the same fallback
  host is used for many domains, so all can be sent in a single transaction
  (if appropriately configured). */

  if (addr_fallback != NULL && !mua_wrapper)
    {
    DEBUG(D_deliver) debug_printf("Delivering to fallback hosts\n");
    addr_remote = addr_fallback;
    addr_fallback = NULL;
    if (remote_sort_domains != NULL) sort_remote_deliveries();
    do_remote_deliveries(TRUE);
    }
  disable_logging = FALSE;
  }


/* All deliveries are now complete. Ignore SIGTERM during this tidying up
phase, to minimize cases of half-done things. */

DEBUG(D_deliver)
  debug_printf(">>>>>>>>>>>>>>>> deliveries are done >>>>>>>>>>>>>>>>\n");

/* Root privilege is no longer needed */

exim_setugid(exim_uid, exim_gid, FALSE, US"post-delivery tidying");

set_process_info("tidying up after delivering %s", message_id);
signal(SIGTERM, SIG_IGN);

/* When we are acting as an MUA wrapper, the smtp transport will either have
succeeded for all addresses, or failed them all in normal cases. However, there
are some setup situations (e.g. when a named port does not exist) that cause an
immediate exit with deferral of all addresses. Convert those into failures. We
do not ever want to retry, nor do we want to send a bounce message. */

if (mua_wrapper)
  {
  if (addr_defer != NULL)
    {
    address_item *addr, *nextaddr;
    for (addr = addr_defer; addr != NULL; addr = nextaddr)
      {
      log_write(0, LOG_MAIN, "** %s mua_wrapper forced failure for deferred "
        "delivery", addr->address);
      nextaddr = addr->next;
      addr->next = addr_failed;
      addr_failed = addr;
      }
    addr_defer = NULL;
    }

  /* Now all should either have succeeded or failed. */

  if (addr_failed == NULL) final_yield = DELIVER_MUA_SUCCEEDED; else
    {
    uschar *s = (addr_failed->user_message != NULL)?
      addr_failed->user_message : addr_failed->message;
    host_item * host;

    fprintf(stderr, "Delivery failed: ");
    if (addr_failed->basic_errno > 0)
      {
      fprintf(stderr, "%s", strerror(addr_failed->basic_errno));
      if (s != NULL) fprintf(stderr, ": ");
      }
    if ((host = addr_failed->host_used))
      fprintf(stderr, "H=%s [%s]: ", host->name, host->address);
    if (s == NULL)
      {
      if (addr_failed->basic_errno <= 0) fprintf(stderr, "unknown error");
      }
    else fprintf(stderr, "%s", CS s);
    fprintf(stderr, "\n");

    final_yield = DELIVER_MUA_FAILED;
    addr_failed = NULL;
    }
  }

/* In a normal configuration, we now update the retry database. This is done in
one fell swoop at the end in order not to keep opening and closing (and
locking) the database. The code for handling retries is hived off into a
separate module for convenience. We pass it the addresses of the various
chains, because deferred addresses can get moved onto the failed chain if the
retry cutoff time has expired for all alternative destinations. Bypass the
updating of the database if the -N flag is set, which is a debugging thing that
prevents actual delivery. */

else if (!dont_deliver) retry_update(&addr_defer, &addr_failed, &addr_succeed);

/* Send DSN for successful messages */
addr_dsntmp = addr_succeed;
addr_senddsn = NULL;

while(addr_dsntmp)
  {
  /* af_ignore_error not honored here. it's not an error */
  DEBUG(D_deliver)
    {
    debug_printf("DSN: processing router : %s\n"
      "DSN: processing successful delivery address: %s\n"
      "DSN: Sender_address: %s\n"
      "DSN: orcpt: %s  flags: %d\n"
      "DSN: envid: %s  ret: %d\n"
      "DSN: Final recipient: %s\n"
      "DSN: Remote SMTP server supports DSN: %d\n",
      addr_dsntmp->router->name,
      addr_dsntmp->address,
      sender_address,
      addr_dsntmp->dsn_orcpt, addr_dsntmp->dsn_flags,
      dsn_envid, dsn_ret,
      addr_dsntmp->address,
      addr_dsntmp->dsn_aware
      );
    }

  /* send report if next hop not DSN aware or a router flagged "last DSN hop"
     and a report was requested */
  if (  (  addr_dsntmp->dsn_aware != dsn_support_yes
	|| addr_dsntmp->dsn_flags & rf_dsnlasthop
        )
     && addr_dsntmp->dsn_flags & rf_dsnflags
     && addr_dsntmp->dsn_flags & rf_notify_success
     )
    {
    /* copy and relink address_item and send report with all of them at once later */
    address_item *addr_next;
    addr_next = addr_senddsn;
    addr_senddsn = store_get(sizeof(address_item));
    memcpy(addr_senddsn, addr_dsntmp, sizeof(address_item));
    addr_senddsn->next = addr_next;
    }
  else
    DEBUG(D_deliver) debug_printf("DSN: not sending DSN success message\n"); 

  addr_dsntmp = addr_dsntmp->next;
  }

if (addr_senddsn)
  {
  pid_t pid;
  int fd;

  /* create exim process to send message */      
  pid = child_open_exim(&fd);

  DEBUG(D_deliver) debug_printf("DSN: child_open_exim returns: %d\n", pid);
     
  if (pid < 0)  /* Creation of child failed */
    {
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "Process %d (parent %d) failed to "
      "create child process to send failure message: %s", getpid(),
      getppid(), strerror(errno));

    DEBUG(D_deliver) debug_printf("DSN: child_open_exim failed\n");
    }    
  else  /* Creation of child succeeded */
    {
    FILE *f = fdopen(fd, "wb");
    /* header only as required by RFC. only failure DSN needs to honor RET=FULL */
    int topt = topt_add_return_path | topt_no_body;
    uschar * bound;
     
    DEBUG(D_deliver)
      debug_printf("sending error message to: %s\n", sender_address);
  
    /* build unique id for MIME boundary */
    bound = string_sprintf(TIME_T_FMT "-eximdsn-%d", time(NULL), rand());
    DEBUG(D_deliver) debug_printf("DSN: MIME boundary: %s\n", bound);
  
    if (errors_reply_to)
      fprintf(f, "Reply-To: %s\n", errors_reply_to);
 
    fprintf(f, "Auto-Submitted: auto-generated\n"
	"From: Mail Delivery System <Mailer-Daemon@%s>\n"
	"To: %s\n"
	"Subject: Delivery Status Notification\n"
	"Content-Type: multipart/report; report-type=delivery-status; boundary=%s\n"
	"MIME-Version: 1.0\n\n"

	"--%s\n"
	"Content-type: text/plain; charset=us-ascii\n\n"
   
	"This message was created automatically by mail delivery software.\n"
	" ----- The following addresses had successful delivery notifications -----\n",
      qualify_domain_sender, sender_address, bound, bound);

    for (addr_dsntmp = addr_senddsn; addr_dsntmp;
	 addr_dsntmp = addr_dsntmp->next)
      fprintf(f, "<%s> (relayed %s)\n\n",
	addr_dsntmp->address,
	(addr_dsntmp->dsn_flags & rf_dsnlasthop) == 1
	  ? "via non DSN router"
	  : addr_dsntmp->dsn_aware == dsn_support_no
	  ? "to non-DSN-aware mailer"
	  : "via non \"Remote SMTP\" router"
	);

    fprintf(f, "--%s\n"
	"Content-type: message/delivery-status\n\n"
	"Reporting-MTA: dns; %s\n",
      bound, smtp_active_hostname);

    if (dsn_envid)
      {			/* must be decoded from xtext: see RFC 3461:6.3a */
      uschar *xdec_envid;
      if (auth_xtextdecode(dsn_envid, &xdec_envid) > 0)
        fprintf(f, "Original-Envelope-ID: %s\n", dsn_envid);
      else
        fprintf(f, "X-Original-Envelope-ID: error decoding xtext formated ENVID\n");
      }
    fputc('\n', f);

    for (addr_dsntmp = addr_senddsn;
	 addr_dsntmp;
	 addr_dsntmp = addr_dsntmp->next)
      {
      if (addr_dsntmp->dsn_orcpt)
        fprintf(f,"Original-Recipient: %s\n", addr_dsntmp->dsn_orcpt);

      fprintf(f, "Action: delivered\n"
	  "Final-Recipient: rfc822;%s\n"
	  "Status: 2.0.0\n",
	addr_dsntmp->address);

      if (addr_dsntmp->host_used && addr_dsntmp->host_used->name)
        fprintf(f, "Remote-MTA: dns; %s\nDiagnostic-Code: smtp; 250 Ok\n\n",
	  addr_dsntmp->host_used->name);
      else
	fprintf(f, "Diagnostic-Code: X-Exim; relayed via non %s router\n\n",
	  (addr_dsntmp->dsn_flags & rf_dsnlasthop) == 1 ? "DSN" : "SMTP");
      }

    fprintf(f, "--%s\nContent-type: text/rfc822-headers\n\n", bound);
           
    fflush(f);
    transport_filter_argv = NULL;   /* Just in case */
    return_path = sender_address;   /* In case not previously set */
           
    /* Write the original email out */
    transport_write_message(NULL, fileno(f), topt, 0, NULL, NULL, NULL, NULL, NULL, 0);
    fflush(f);

    fprintf(f,"\n--%s--\n", bound);

    fflush(f);
    fclose(f);
    rc = child_close(pid, 0);     /* Waits for child to close, no timeout */
    }
  }

/* If any addresses failed, we must send a message to somebody, unless
af_ignore_error is set, in which case no action is taken. It is possible for
several messages to get sent if there are addresses with different
requirements. */

while (addr_failed != NULL)
  {
  pid_t pid;
  int fd;
  uschar *logtod = tod_stamp(tod_log);
  address_item *addr;
  address_item *handled_addr = NULL;
  address_item **paddr;
  address_item *msgchain = NULL;
  address_item **pmsgchain = &msgchain;

  /* There are weird cases when logging is disabled in the transport. However,
  there may not be a transport (address failed by a router). */

  disable_logging = FALSE;
  if (addr_failed->transport != NULL)
    disable_logging = addr_failed->transport->disable_logging;

  DEBUG(D_deliver)
    debug_printf("processing failed address %s\n", addr_failed->address);

  /* There are only two ways an address in a bounce message can get here:

  (1) When delivery was initially deferred, but has now timed out (in the call
      to retry_update() above). We can detect this by testing for
      af_retry_timedout. If the address does not have its own errors address,
      we arrange to ignore the error.

  (2) If delivery failures for bounce messages are being ignored. We can detect
      this by testing for af_ignore_error. This will also be set if a bounce
      message has been autothawed and the ignore_bounce_errors_after time has
      passed. It might also be set if a router was explicitly configured to
      ignore errors (errors_to = "").

  If neither of these cases obtains, something has gone wrong. Log the
  incident, but then ignore the error. */

  if (sender_address[0] == 0 && addr_failed->prop.errors_address == NULL)
    {
    if (  !testflag(addr_failed, af_retry_timedout)
       && !testflag(addr_failed, af_ignore_error))
      {
      log_write(0, LOG_MAIN|LOG_PANIC, "internal error: bounce message "
        "failure is neither frozen nor ignored (it's been ignored)");
      }
    setflag(addr_failed, af_ignore_error);
    }

  /* If the first address on the list has af_ignore_error set, just remove
  it from the list, throw away any saved message file, log it, and
  mark the recipient done. */

  if (  testflag(addr_failed, af_ignore_error)
     || (  addr_failed->dsn_flags & rf_dsnflags
        && (addr_failed->dsn_flags & rf_notify_failure) != rf_notify_failure)
     )
    {
    addr = addr_failed;
    addr_failed = addr->next;
    if (addr->return_filename != NULL) Uunlink(addr->return_filename);

    log_write(0, LOG_MAIN, "%s%s%s%s: error ignored",
      addr->address,
      !addr->parent ? US"" : US" <",
      !addr->parent ? US"" : addr->parent->address,
      !addr->parent ? US"" : US">");

    address_done(addr, logtod);
    child_done(addr, logtod);
    /* Panic-dies on error */
    (void)spool_write_header(message_id, SW_DELIVERING, NULL);
    }

  /* Otherwise, handle the sending of a message. Find the error address for
  the first address, then send a message that includes all failed addresses
  that have the same error address. Note the bounce_recipient is a global so
  that it can be accesssed by $bounce_recipient while creating a customized
  error message. */

  else
    {
    bounce_recipient = addr_failed->prop.errors_address
      ? addr_failed->prop.errors_address : sender_address;

    /* Make a subprocess to send a message */

    if ((pid = child_open_exim(&fd)) < 0)
      log_write(0, LOG_MAIN|LOG_PANIC_DIE, "Process %d (parent %d) failed to "
        "create child process to send failure message: %s", getpid(),
        getppid(), strerror(errno));

    /* Creation of child succeeded */

    else
      {
      int ch, rc;
      int filecount = 0;
      int rcount = 0;
      uschar *bcc, *emf_text;
      FILE *f = fdopen(fd, "wb");
      FILE *emf = NULL;
      BOOL to_sender = strcmpic(sender_address, bounce_recipient) == 0;
      int max = (bounce_return_size_limit/DELIVER_IN_BUFFER_SIZE + 1) *
        DELIVER_IN_BUFFER_SIZE;
      uschar * bound;
      uschar *dsnlimitmsg;
      uschar *dsnnotifyhdr;
      int topt;

      DEBUG(D_deliver)
        debug_printf("sending error message to: %s\n", bounce_recipient);

      /* Scan the addresses for all that have the same errors address, removing
      them from the addr_failed chain, and putting them on msgchain. */

      paddr = &addr_failed;
      for (addr = addr_failed; addr != NULL; addr = *paddr)
        if (Ustrcmp(bounce_recipient, addr->prop.errors_address
	      ? addr->prop.errors_address : sender_address) == 0)
          {                          /* The same - dechain */
          *paddr = addr->next;
          *pmsgchain = addr;
          addr->next = NULL;
          pmsgchain = &(addr->next);
          }
        else
          paddr = &addr->next;        /* Not the same; skip */

      /* Include X-Failed-Recipients: for automatic interpretation, but do
      not let any one header line get too long. We do this by starting a
      new header every 50 recipients. Omit any addresses for which the
      "hide_child" flag is set. */

      for (addr = msgchain; addr != NULL; addr = addr->next)
        {
        if (testflag(addr, af_hide_child)) continue;
        if (rcount >= 50)
          {
          fprintf(f, "\n");
          rcount = 0;
          }
        fprintf(f, "%s%s",
          (rcount++ == 0)? "X-Failed-Recipients: " : ",\n  ",
          (testflag(addr, af_pfr) && addr->parent != NULL)?
            string_printing(addr->parent->address) :
            string_printing(addr->address));
        }
      if (rcount > 0) fprintf(f, "\n");

      /* Output the standard headers */

      if (errors_reply_to)
        fprintf(f, "Reply-To: %s\n", errors_reply_to);
      fprintf(f, "Auto-Submitted: auto-replied\n");
      moan_write_from(f);
      fprintf(f, "To: %s\n", bounce_recipient);

      /* generate boundary string and output MIME-Headers */
      bound = string_sprintf(TIME_T_FMT "-eximdsn-%d", time(NULL), rand());

      fprintf(f, "Content-Type: multipart/report;"
	    " report-type=delivery-status; boundary=%s\n"
	  "MIME-Version: 1.0\n",
	bound);

      /* Open a template file if one is provided. Log failure to open, but
      carry on - default texts will be used. */

      if (bounce_message_file)
        if (!(emf = Ufopen(bounce_message_file, "rb")))
          log_write(0, LOG_MAIN|LOG_PANIC, "Failed to open %s for error "
            "message texts: %s", bounce_message_file, strerror(errno));

      /* Quietly copy to configured additional addresses if required. */

      if ((bcc = moan_check_errorcopy(bounce_recipient)))
	fprintf(f, "Bcc: %s\n", bcc);

      /* The texts for the message can be read from a template file; if there
      isn't one, or if it is too short, built-in texts are used. The first
      emf text is a Subject: and any other headers. */

      if ((emf_text = next_emf(emf, US"header")))
	fprintf(f, "%s\n", emf_text);
      else
        fprintf(f, "Subject: Mail delivery failed%s\n\n",
          to_sender? ": returning message to sender" : "");

      /* output human readable part as text/plain section */
      fprintf(f, "--%s\n"
	  "Content-type: text/plain; charset=us-ascii\n\n",
	bound);

      if ((emf_text = next_emf(emf, US"intro")))
	fprintf(f, "%s", CS emf_text);
      else
        {
        fprintf(f,
/* This message has been reworded several times. It seems to be confusing to
somebody, however it is worded. I have retreated to the original, simple
wording. */
"This message was created automatically by mail delivery software.\n");

        if (bounce_message_text)
	  fprintf(f, "%s", CS bounce_message_text);
        if (to_sender)
          fprintf(f,
"\nA message that you sent could not be delivered to one or more of its\n"
"recipients. This is a permanent error. The following address(es) failed:\n");
        else
          fprintf(f,
"\nA message sent by\n\n  <%s>\n\n"
"could not be delivered to one or more of its recipients. The following\n"
"address(es) failed:\n", sender_address);
        }
      fputc('\n', f);

      /* Process the addresses, leaving them on the msgchain if they have a
      file name for a return message. (There has already been a check in
      post_process_one() for the existence of data in the message file.) A TRUE
      return from print_address_information() means that the address is not
      hidden. */

      paddr = &msgchain;
      for (addr = msgchain; addr != NULL; addr = *paddr)
        {
        if (print_address_information(addr, f, US"  ", US"\n    ", US""))
          print_address_error(addr, f, US"");

        /* End the final line for the address */

        fputc('\n', f);

        /* Leave on msgchain if there's a return file. */

        if (addr->return_file >= 0)
          {
          paddr = &(addr->next);
          filecount++;
          }

        /* Else save so that we can tick off the recipient when the
        message is sent. */

        else
          {
          *paddr = addr->next;
          addr->next = handled_addr;
          handled_addr = addr;
          }
        }

      fputc('\n', f);

      /* Get the next text, whether we need it or not, so as to be
      positioned for the one after. */

      emf_text = next_emf(emf, US"generated text");

      /* If there were any file messages passed by the local transports,
      include them in the message. Then put the address on the handled chain.
      In the case of a batch of addresses that were all sent to the same
      transport, the return_file field in all of them will contain the same
      fd, and the return_filename field in the *last* one will be set (to the
      name of the file). */

      if (msgchain)
        {
        address_item *nextaddr;

        if (emf_text)
	  fprintf(f, "%s", CS emf_text);
	else
          fprintf(f,
            "The following text was generated during the delivery "
            "attempt%s:\n", (filecount > 1)? "s" : "");

        for (addr = msgchain; addr != NULL; addr = nextaddr)
          {
          FILE *fm;
          address_item *topaddr = addr;

          /* List all the addresses that relate to this file */

	  fputc('\n', f);
          while(addr)                   /* Insurance */
            {
            print_address_information(addr, f, US"------ ",  US"\n       ",
              US" ------\n");
            if (addr->return_filename) break;
            addr = addr->next;
            }
	  fputc('\n', f);

          /* Now copy the file */

          fm = Ufopen(addr->return_filename, "rb");

          if (fm == NULL)
            fprintf(f, "    +++ Exim error... failed to open text file: %s\n",
              strerror(errno));
          else
            {
            while ((ch = fgetc(fm)) != EOF) fputc(ch, f);
            (void)fclose(fm);
            }
          Uunlink(addr->return_filename);

          /* Can now add to handled chain, first fishing off the next
          address on the msgchain. */

          nextaddr = addr->next;
          addr->next = handled_addr;
          handled_addr = topaddr;
          }
	fputc('\n', f);
        }

      /* output machine readable part */
#ifdef EXPERIMENTAL_INTERNATIONAL
      if (message_smtputf8)
	fprintf(f, "--%s\n"
	    "Content-type: message/global-delivery-status\n\n"
	    "Reporting-MTA: dns; %s\n",
	  bound, smtp_active_hostname);
      else
#endif
	fprintf(f, "--%s\n"
	    "Content-type: message/delivery-status\n\n"
	    "Reporting-MTA: dns; %s\n",
	  bound, smtp_active_hostname);

      if (dsn_envid)
	{
        /* must be decoded from xtext: see RFC 3461:6.3a */
        uschar *xdec_envid;
        if (auth_xtextdecode(dsn_envid, &xdec_envid) > 0)
          fprintf(f, "Original-Envelope-ID: %s\n", dsn_envid);
        else
          fprintf(f, "X-Original-Envelope-ID: error decoding xtext formated ENVID\n");
        }
      fputc('\n', f);
 
      for (addr = handled_addr; addr; addr = addr->next)
        {
        fprintf(f, "Action: failed\n"
	    "Final-Recipient: rfc822;%s\n"
	    "Status: 5.0.0\n",
	    addr->address);
        if (addr->host_used && addr->host_used->name)
          {
          fprintf(f, "Remote-MTA: dns; %s\n",
	    addr->host_used->name);
          print_dsn_diagnostic_code(addr, f);
          }
	fputc('\n', f);
        }

      /* Now copy the message, trying to give an intelligible comment if
      it is too long for it all to be copied. The limit isn't strictly
      applied because of the buffering. There is, however, an option
      to suppress copying altogether. */

      emf_text = next_emf(emf, US"copy");

      /* add message body
         we ignore the intro text from template and add 
         the text for bounce_return_size_limit at the end.
  
         bounce_return_message is ignored
         in case RET= is defined we honor these values
         otherwise bounce_return_body is honored.
         
         bounce_return_size_limit is always honored.
      */
  
      fprintf(f, "--%s\n", bound);

      dsnlimitmsg = US"X-Exim-DSN-Information: Due to administrative limits only headers are returned";
      dsnnotifyhdr = NULL;
      topt = topt_add_return_path;

      /* RET=HDRS? top priority */
      if (dsn_ret == dsn_ret_hdrs)
        topt |= topt_no_body;
      else
        /* no full body return at all? */
        if (!bounce_return_body)
          {
          topt |= topt_no_body;
          /* add header if we overrule RET=FULL */
          if (dsn_ret == dsn_ret_full)
            dsnnotifyhdr = dsnlimitmsg;
          }
        /* size limited ... return headers only if limit reached */
        else if (bounce_return_size_limit > 0)
          {
          struct stat statbuf;
          if (fstat(deliver_datafile, &statbuf) == 0 && statbuf.st_size > max)
            {
              topt |= topt_no_body;
              dsnnotifyhdr = dsnlimitmsg;
            }
          }
  
#ifdef EXPERIMENTAL_INTERNATIONAL
      if (message_smtputf8)
	fputs(topt & topt_no_body ? "Content-type: message/global-headers\n\n"
				  : "Content-type: message/global\n\n",
	      f);
      else
#endif
	fputs(topt & topt_no_body ? "Content-type: text/rfc822-headers\n\n"
				  : "Content-type: message/rfc822\n\n",
	      f);

      fflush(f);
      transport_filter_argv = NULL;   /* Just in case */
      return_path = sender_address;   /* In case not previously set */
      transport_write_message(NULL, fileno(f), topt,
        0, dsnnotifyhdr, NULL, NULL, NULL, NULL, 0);
      fflush(f);
 
      /* we never add the final text. close the file */
      if (emf)
        (void)fclose(emf);
 
      fprintf(f, "\n--%s--\n", bound);

      /* Close the file, which should send an EOF to the child process
      that is receiving the message. Wait for it to finish. */

      (void)fclose(f);
      rc = child_close(pid, 0);     /* Waits for child to close, no timeout */

      /* In the test harness, let the child do it's thing first. */

      if (running_in_test_harness) millisleep(500);

      /* If the process failed, there was some disaster in setting up the
      error message. Unless the message is very old, ensure that addr_defer
      is non-null, which will have the effect of leaving the message on the
      spool. The failed addresses will get tried again next time. However, we
      don't really want this to happen too often, so freeze the message unless
      there are some genuine deferred addresses to try. To do this we have
      to call spool_write_header() here, because with no genuine deferred
      addresses the normal code below doesn't get run. */

      if (rc != 0)
        {
        uschar *s = US"";
        if (now - received_time < retry_maximum_timeout && addr_defer == NULL)
          {
          addr_defer = (address_item *)(+1);
          deliver_freeze = TRUE;
          deliver_frozen_at = time(NULL);
          /* Panic-dies on error */
          (void)spool_write_header(message_id, SW_DELIVERING, NULL);
          s = US" (frozen)";
          }
        deliver_msglog("Process failed (%d) when writing error message "
          "to %s%s", rc, bounce_recipient, s);
        log_write(0, LOG_MAIN, "Process failed (%d) when writing error message "
          "to %s%s", rc, bounce_recipient, s);
        }

      /* The message succeeded. Ensure that the recipients that failed are
      now marked finished with on the spool and their parents updated. */

      else
        {
        for (addr = handled_addr; addr != NULL; addr = addr->next)
          {
          address_done(addr, logtod);
          child_done(addr, logtod);
          }
        /* Panic-dies on error */
        (void)spool_write_header(message_id, SW_DELIVERING, NULL);
        }
      }
    }
  }

disable_logging = FALSE;  /* In case left set */

/* Come here from the mua_wrapper case if routing goes wrong */

DELIVERY_TIDYUP:

/* If there are now no deferred addresses, we are done. Preserve the
message log if so configured, and we are using them. Otherwise, sling it.
Then delete the message itself. */

if (addr_defer == NULL)
  {
  if (message_logs)
    {
    sprintf(CS spoolname, "%s/msglog/%s/%s", spool_directory, message_subdir,
      id);
    if (preserve_message_logs)
      {
      int rc;
      sprintf(CS big_buffer, "%s/msglog.OLD/%s", spool_directory, id);
      if ((rc = Urename(spoolname, big_buffer)) < 0)
        {
        (void)directory_make(spool_directory, US"msglog.OLD",
          MSGLOG_DIRECTORY_MODE, TRUE);
        rc = Urename(spoolname, big_buffer);
        }
      if (rc < 0)
        log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to move %s to the "
          "msglog.OLD directory", spoolname);
      }
    else
      if (Uunlink(spoolname) < 0)
        log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to unlink %s: %s",
		  spoolname, strerror(errno));
    }

  /* Remove the two message files. */

  sprintf(CS spoolname, "%s/input/%s/%s-D", spool_directory, message_subdir, id);
  if (Uunlink(spoolname) < 0)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to unlink %s: %s",
      spoolname, strerror(errno));
  sprintf(CS spoolname, "%s/input/%s/%s-H", spool_directory, message_subdir, id);
  if (Uunlink(spoolname) < 0)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to unlink %s: %s",
      spoolname, strerror(errno));

  /* Log the end of this message, with queue time if requested. */

  if ((log_extra_selector & LX_queue_time_overall) != 0)
    log_write(0, LOG_MAIN, "Completed QT=%s",
      readconf_printtime( (int) ((long)time(NULL) - (long)received_time)) );
  else
    log_write(0, LOG_MAIN, "Completed");

  /* Unset deliver_freeze so that we won't try to move the spool files further down */
  deliver_freeze = FALSE;

#ifdef EXPERIMENTAL_EVENT
  (void) event_raise(event_action, US"msg:complete", NULL);
#endif
}

/* If there are deferred addresses, we are keeping this message because it is
not yet completed. Lose any temporary files that were catching output from
pipes for any of the deferred addresses, handle one-time aliases, and see if
the message has been on the queue for so long that it is time to send a warning
message to the sender, unless it is a mailer-daemon. If all deferred addresses
have the same domain, we can set deliver_domain for the expansion of
delay_warning_ condition - if any of them are pipes, files, or autoreplies, use
the parent's domain.

If all the deferred addresses have an error number that indicates "retry time
not reached", skip sending the warning message, because it won't contain the
reason for the delay. It will get sent at the next real delivery attempt.
However, if at least one address has tried, we'd better include all of them in
the message.

If we can't make a process to send the message, don't worry.

For mailing list expansions we want to send the warning message to the
mailing list manager. We can't do a perfect job here, as some addresses may
have different errors addresses, but if we take the errors address from
each deferred address it will probably be right in most cases.

If addr_defer == +1, it means there was a problem sending an error message
for failed addresses, and there were no "real" deferred addresses. The value
was set just to keep the message on the spool, so there is nothing to do here.
*/

else if (addr_defer != (address_item *)(+1))
  {
  address_item *addr;
  uschar *recipients = US"";
  BOOL delivery_attempted = FALSE;

  deliver_domain = testflag(addr_defer, af_pfr)?
    addr_defer->parent->domain : addr_defer->domain;

  for (addr = addr_defer; addr != NULL; addr = addr->next)
    {
    address_item *otaddr;

    if (addr->basic_errno > ERRNO_RETRY_BASE) delivery_attempted = TRUE;

    if (deliver_domain != NULL)
      {
      const uschar *d = testflag(addr, af_pfr)
	? addr->parent->domain : addr->domain;

      /* The domain may be unset for an address that has never been routed
      because the system filter froze the message. */

      if (d == NULL || Ustrcmp(d, deliver_domain) != 0) deliver_domain = NULL;
      }

    if (addr->return_filename != NULL) Uunlink(addr->return_filename);

    /* Handle the case of one-time aliases. If any address in the ancestry
    of this one is flagged, ensure it is in the recipients list, suitably
    flagged, and that its parent is marked delivered. */

    for (otaddr = addr; otaddr != NULL; otaddr = otaddr->parent)
      if (otaddr->onetime_parent != NULL) break;

    if (otaddr != NULL)
      {
      int i;
      int t = recipients_count;

      for (i = 0; i < recipients_count; i++)
        {
        uschar *r = recipients_list[i].address;
        if (Ustrcmp(otaddr->onetime_parent, r) == 0) t = i;
        if (Ustrcmp(otaddr->address, r) == 0) break;
        }

      /* Didn't find the address already in the list, and did find the
      ultimate parent's address in the list. After adding the recipient,
      update the errors address in the recipients list. */

      if (i >= recipients_count && t < recipients_count)
        {
        DEBUG(D_deliver) debug_printf("one_time: adding %s in place of %s\n",
          otaddr->address, otaddr->parent->address);
        receive_add_recipient(otaddr->address, t);
        recipients_list[recipients_count-1].errors_to = otaddr->prop.errors_address;
        tree_add_nonrecipient(otaddr->parent->address);
        update_spool = TRUE;
        }
      }

    /* Except for error messages, ensure that either the errors address for
    this deferred address or, if there is none, the sender address, is on the
    list of recipients for a warning message. */

    if (sender_address[0] != 0)
      {
      if (addr->prop.errors_address == NULL)
        {
        if (Ustrstr(recipients, sender_address) == NULL)
          recipients = string_sprintf("%s%s%s", recipients,
            (recipients[0] == 0)? "" : ",", sender_address);
        }
      else
        {
        if (Ustrstr(recipients, addr->prop.errors_address) == NULL)
          recipients = string_sprintf("%s%s%s", recipients,
            (recipients[0] == 0)? "" : ",", addr->prop.errors_address);
        }
      }
    }

  /* Send a warning message if the conditions are right. If the condition check
  fails because of a lookup defer, there is nothing we can do. The warning
  is not sent. Another attempt will be made at the next delivery attempt (if
  it also defers). */

  if (  !queue_2stage
     && delivery_attempted
     && (  ((addr_defer->dsn_flags & rf_dsnflags) == 0)
        || (addr_defer->dsn_flags & rf_notify_delay) == rf_notify_delay
	)
     && delay_warning[1] > 0
     && sender_address[0] != 0
     && (  delay_warning_condition == NULL
        || expand_check_condition(delay_warning_condition,
            US"delay_warning", US"option")
	)
     )
    {
    int count;
    int show_time;
    int queue_time = time(NULL) - received_time;

    /* When running in the test harness, there's an option that allows us to
    fudge this time so as to get repeatability of the tests. Take the first
    time off the list. In queue runs, the list pointer gets updated in the
    calling process. */

    if (running_in_test_harness && fudged_queue_times[0] != 0)
      {
      int qt = readconf_readtime(fudged_queue_times, '/', FALSE);
      if (qt >= 0)
        {
        DEBUG(D_deliver) debug_printf("fudged queue_times = %s\n",
          fudged_queue_times);
        queue_time = qt;
        }
      }

    /* See how many warnings we should have sent by now */

    for (count = 0; count < delay_warning[1]; count++)
      if (queue_time < delay_warning[count+2]) break;

    show_time = delay_warning[count+1];

    if (count >= delay_warning[1])
      {
      int extra;
      int last_gap = show_time;
      if (count > 1) last_gap -= delay_warning[count];
      extra = (queue_time - delay_warning[count+1])/last_gap;
      show_time += last_gap * extra;
      count += extra;
      }

    DEBUG(D_deliver)
      {
      debug_printf("time on queue = %s\n", readconf_printtime(queue_time));
      debug_printf("warning counts: required %d done %d\n", count,
        warning_count);
      }

    /* We have computed the number of warnings there should have been by now.
    If there haven't been enough, send one, and up the count to what it should
    have been. */

    if (warning_count < count)
      {
      header_line *h;
      int fd;
      pid_t pid = child_open_exim(&fd);

      if (pid > 0)
        {
        uschar *wmf_text;
        FILE *wmf = NULL;
        FILE *f = fdopen(fd, "wb");
	uschar * bound;

        if (warn_message_file)
          {
          wmf = Ufopen(warn_message_file, "rb");
          if (wmf == NULL)
            log_write(0, LOG_MAIN|LOG_PANIC, "Failed to open %s for warning "
              "message texts: %s", warn_message_file, strerror(errno));
          }

        warnmsg_recipients = recipients;
        warnmsg_delay = (queue_time < 120*60)?
          string_sprintf("%d minutes", show_time/60):
          string_sprintf("%d hours", show_time/3600);

        if (errors_reply_to)
          fprintf(f, "Reply-To: %s\n", errors_reply_to);
        fprintf(f, "Auto-Submitted: auto-replied\n");
        moan_write_from(f);
        fprintf(f, "To: %s\n", recipients);

        /* generated boundary string and output MIME-Headers */
        bound = string_sprintf(TIME_T_FMT "-eximdsn-%d", time(NULL), rand());

        fprintf(f, "Content-Type: multipart/report;"
	    " report-type=delivery-status; boundary=%s\n"
	    "MIME-Version: 1.0\n",
	  bound);

        if ((wmf_text = next_emf(wmf, US"header")))
          fprintf(f, "%s\n", wmf_text);
        else
          fprintf(f, "Subject: Warning: message %s delayed %s\n\n",
            message_id, warnmsg_delay);

        /* output human readable part as text/plain section */
        fprintf(f, "--%s\n"
	    "Content-type: text/plain; charset=us-ascii\n\n",
	  bound);

        if ((wmf_text = next_emf(wmf, US"intro")))
	  fprintf(f, "%s", CS wmf_text);
	else
          {
          fprintf(f,
"This message was created automatically by mail delivery software.\n");

          if (Ustrcmp(recipients, sender_address) == 0)
            fprintf(f,
"A message that you sent has not yet been delivered to one or more of its\n"
"recipients after more than ");

          else
	    fprintf(f,
"A message sent by\n\n  <%s>\n\n"
"has not yet been delivered to one or more of its recipients after more than \n",
	      sender_address);

          fprintf(f, "%s on the queue on %s.\n\n"
	      "The message identifier is:     %s\n",
	    warnmsg_delay, primary_hostname, message_id);

          for (h = header_list; h != NULL; h = h->next)
            if (strncmpic(h->text, US"Subject:", 8) == 0)
              fprintf(f, "The subject of the message is: %s", h->text + 9);
            else if (strncmpic(h->text, US"Date:", 5) == 0)
              fprintf(f, "The date of the message is:    %s", h->text + 6);
          fputc('\n', f);

          fprintf(f, "The address%s to which the message has not yet been "
            "delivered %s:\n",
            !addr_defer->next ? "" : "es",
            !addr_defer->next ? "is": "are");
          }

        /* List the addresses, with error information if allowed */

        /* store addr_defer for machine readable part */
        address_item *addr_dsndefer = addr_defer;
        fputc('\n', f);
        while (addr_defer)
          {
          address_item *addr = addr_defer;
          addr_defer = addr->next;
          if (print_address_information(addr, f, US"  ", US"\n    ", US""))
            print_address_error(addr, f, US"Delay reason: ");
          fputc('\n', f);
          }
        fputc('\n', f);

        /* Final text */

        if (wmf)
          {
          if ((wmf_text = next_emf(wmf, US"final")))
	    fprintf(f, "%s", CS wmf_text);
          (void)fclose(wmf);
          }
        else
          {
          fprintf(f,
"No action is required on your part. Delivery attempts will continue for\n"
"some time, and this warning may be repeated at intervals if the message\n"
"remains undelivered. Eventually the mail delivery software will give up,\n"
"and when that happens, the message will be returned to you.\n");
          }

        /* output machine readable part */
        fprintf(f, "\n--%s\n"
	    "Content-type: message/delivery-status\n\n"
	    "Reporting-MTA: dns; %s\n",
	  bound,
	  smtp_active_hostname);
 

        if (dsn_envid)
	  {
          /* must be decoded from xtext: see RFC 3461:6.3a */
          uschar *xdec_envid;
          if (auth_xtextdecode(dsn_envid, &xdec_envid) > 0)
            fprintf(f,"Original-Envelope-ID: %s\n", dsn_envid);
          else
            fprintf(f,"X-Original-Envelope-ID: error decoding xtext formated ENVID\n");
          }
        fputc('\n', f);

        for ( ; addr_dsndefer; addr_dsndefer = addr_dsndefer->next)
          {
          if (addr_dsndefer->dsn_orcpt)
            fprintf(f, "Original-Recipient: %s\n", addr_dsndefer->dsn_orcpt);

          fprintf(f, "Action: delayed\n"
	      "Final-Recipient: rfc822;%s\n"
	      "Status: 4.0.0\n",
	    addr_dsndefer->address);
          if (addr_dsndefer->host_used && addr_dsndefer->host_used->name)
            {
            fprintf(f, "Remote-MTA: dns; %s\n", 
		    addr_dsndefer->host_used->name);
            print_dsn_diagnostic_code(addr_dsndefer, f);
            }
	  fputc('\n', f);
          }

        fprintf(f, "--%s\n"
	    "Content-type: text/rfc822-headers\n\n",
	  bound);

        fflush(f);
        /* header only as required by RFC. only failure DSN needs to honor RET=FULL */
        int topt = topt_add_return_path | topt_no_body;
        transport_filter_argv = NULL;   /* Just in case */
        return_path = sender_address;   /* In case not previously set */
        /* Write the original email out */
        transport_write_message(NULL, fileno(f), topt, 0, NULL, NULL, NULL, NULL, NULL, 0);
        fflush(f);

        fprintf(f,"\n--%s--\n", bound);

        fflush(f);

        /* Close and wait for child process to complete, without a timeout.
        If there's an error, don't update the count. */

        (void)fclose(f);
        if (child_close(pid, 0) == 0)
          {
          warning_count = count;
          update_spool = TRUE;    /* Ensure spool rewritten */
          }
        }
      }
    }

  /* Clear deliver_domain */

  deliver_domain = NULL;

  /* If this was a first delivery attempt, unset the first time flag, and
  ensure that the spool gets updated. */

  if (deliver_firsttime)
    {
    deliver_firsttime = FALSE;
    update_spool = TRUE;
    }

  /* If delivery was frozen and freeze_tell is set, generate an appropriate
  message, unless the message is a local error message (to avoid loops). Then
  log the freezing. If the text in "frozen_info" came from a system filter,
  it has been escaped into printing characters so as not to mess up log lines.
  For the "tell" message, we turn \n back into newline. Also, insert a newline
  near the start instead of the ": " string. */

  if (deliver_freeze)
    {
    if (freeze_tell != NULL && freeze_tell[0] != 0 && !local_error_message)
      {
      uschar *s = string_copy(frozen_info);
      uschar *ss = Ustrstr(s, " by the system filter: ");

      if (ss != NULL)
        {
        ss[21] = '.';
        ss[22] = '\n';
        }

      ss = s;
      while (*ss != 0)
        {
        if (*ss == '\\' && ss[1] == 'n')
          {
          *ss++ = ' ';
          *ss++ = '\n';
          }
        else ss++;
        }
      moan_tell_someone(freeze_tell, addr_defer, US"Message frozen",
        "Message %s has been frozen%s.\nThe sender is <%s>.\n", message_id,
        s, sender_address);
      }

    /* Log freezing just before we update the -H file, to minimize the chance
    of a race problem. */

    deliver_msglog("*** Frozen%s\n", frozen_info);
    log_write(0, LOG_MAIN, "Frozen%s", frozen_info);
    }

  /* If there have been any updates to the non-recipients list, or other things
  that get written to the spool, we must now update the spool header file so
  that it has the right information for the next delivery attempt. If there
  was more than one address being delivered, the header_change update is done
  earlier, in case one succeeds and then something crashes. */

  DEBUG(D_deliver)
    debug_printf("delivery deferred: update_spool=%d header_rewritten=%d\n",
      update_spool, header_rewritten);

  if (update_spool || header_rewritten)
    /* Panic-dies on error */
    (void)spool_write_header(message_id, SW_DELIVERING, NULL);
  }

/* Finished with the message log. If the message is complete, it will have
been unlinked or renamed above. */

if (message_logs) (void)fclose(message_log);

/* Now we can close and remove the journal file. Its only purpose is to record
successfully completed deliveries asap so that this information doesn't get
lost if Exim (or the machine) crashes. Forgetting about a failed delivery is
not serious, as trying it again is not harmful. The journal might not be open
if all addresses were deferred at routing or directing. Nevertheless, we must
remove it if it exists (may have been lying around from a crash during the
previous delivery attempt). We don't remove the journal if a delivery
subprocess failed to pass back delivery information; this is controlled by
the remove_journal flag. When the journal is left, we also don't move the
message off the main spool if frozen and the option is set. It should get moved
at the next attempt, after the journal has been inspected. */

if (journal_fd >= 0) (void)close(journal_fd);

if (remove_journal)
  {
  sprintf(CS spoolname, "%s/input/%s/%s-J", spool_directory, message_subdir, id);
  if (Uunlink(spoolname) < 0 && errno != ENOENT)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to unlink %s: %s", spoolname,
      strerror(errno));

  /* Move the message off the spool if reqested */

#ifdef SUPPORT_MOVE_FROZEN_MESSAGES
  if (deliver_freeze && move_frozen_messages)
    (void)spool_move_message(id, message_subdir, US"", US"F");
#endif
  }

/* Closing the data file frees the lock; if the file has been unlinked it
will go away. Otherwise the message becomes available for another process
to try delivery. */

(void)close(deliver_datafile);
deliver_datafile = -1;
DEBUG(D_deliver) debug_printf("end delivery of %s\n", id);

/* It is unlikely that there will be any cached resources, since they are
released after routing, and in the delivery subprocesses. However, it's
possible for an expansion for something afterwards (for example,
expand_check_condition) to do a lookup. We must therefore be sure everything is
released. */

search_tidyup();
acl_where = ACL_WHERE_UNKNOWN;
return final_yield;
}



void
deliver_init(void)
{
if (!regex_PIPELINING) regex_PIPELINING =
  regex_must_compile(US"\\n250[\\s\\-]PIPELINING(\\s|\\n|$)", FALSE, TRUE);

if (!regex_SIZE) regex_SIZE =
  regex_must_compile(US"\\n250[\\s\\-]SIZE(\\s|\\n|$)", FALSE, TRUE);

if (!regex_AUTH) regex_AUTH =
  regex_must_compile(US"\\n250[\\s\\-]AUTH\\s+([\\-\\w\\s]+)(?:\\n|$)",
    FALSE, TRUE);

#ifdef SUPPORT_TLS
if (!regex_STARTTLS) regex_STARTTLS =
  regex_must_compile(US"\\n250[\\s\\-]STARTTLS(\\s|\\n|$)", FALSE, TRUE);
#endif

#ifndef DISABLE_PRDR
if (!regex_PRDR) regex_PRDR =
  regex_must_compile(US"\\n250[\\s\\-]PRDR(\\s|\\n|$)", FALSE, TRUE);
#endif

#ifdef EXPERIMENTAL_INTERNATIONAL
if (!regex_UTF8) regex_UTF8 =
  regex_must_compile(US"\\n250[\\s\\-]SMTPUTF8(\\s|\\n|$)", FALSE, TRUE);
#endif

if (!regex_DSN) regex_DSN  =
  regex_must_compile(US"\\n250[\\s\\-]DSN(\\s|\\n|$)", FALSE, TRUE);

if (!regex_IGNOREQUOTA) regex_IGNOREQUOTA =
  regex_must_compile(US"\\n250[\\s\\-]IGNOREQUOTA(\\s|\\n|$)", FALSE, TRUE);
}


uschar *
deliver_get_sender_address (uschar * id)
{
if (!spool_open_datafile(id))
  return NULL;

sprintf(CS spoolname, "%s-H", id);
if (spool_read_header(spoolname, TRUE, TRUE) != spool_read_OK)
  return NULL;

(void)close(deliver_datafile);
deliver_datafile = -1;

return sender_address;
}

/* vi: aw ai sw=2
*/
/* End of deliver.c */
