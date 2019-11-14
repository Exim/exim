/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Wolfgang Breyha 2005 - 2019
 * Vienna University Computer Center
 * wbreyha@gmx.net
 * See the file NOTICE for conditions of use and distribution.
 *
 * Copyright (c) The Exim Maintainers 2015 - 2019
 */

/* Code for calling dccifd. Called from acl.c. */

#include "exim.h"
#ifdef EXPERIMENTAL_DCC
#include "dcc.h"
#include "unistd.h"

#define DCC_HEADER_LIMIT 120

int dcc_ok = 0;
int dcc_rc = 0;

/* This function takes a file descriptor and a buffer as input and
 * returns either 0 for success or errno in case of error. */

int flushbuffer (int socket, gstring *buffer)
{
  int retval, rsp;
  rsp = write(socket, buffer->s, buffer->ptr);
  DEBUG(D_acl)
    debug_printf("DCC: flushbuffer(): Result of the write() = %d\n", rsp);
  if(rsp < 0) {
    DEBUG(D_acl)
      debug_printf("DCC: flushbuffer(): Error writing buffer to socket: %s\n", strerror(errno));
    retval = errno;
  }
  else {
    DEBUG(D_acl)
      debug_printf("DCC: flushbuffer(): Wrote buffer to socket:\n%.*s\n", buffer->ptr, buffer->s);
    retval = 0;
  }
  return retval;
}

int
dcc_process(uschar **listptr)
{
  int sep = 0;
  const uschar *list = *listptr;
  FILE *data_file;
  uschar *dcc_default_ip_option = US"127.0.0.1";
  uschar *dcc_helo_option = US"localhost";
  uschar *xtra_hdrs = NULL;
  uschar *override_client_ip  = NULL;

  /* from local_scan */
  int dcc_resplen, retval, sockfd, resp;
  unsigned int portnr;
  struct sockaddr_un  serv_addr;
  struct sockaddr_in  serv_addr_in;
  struct hostent *ipaddress;
  uschar sockpath[128];
  uschar sockip[40], client_ip[40];
  gstring *dcc_headers;
  gstring *sendbuf;
  uschar *dcc_return_text;
  struct header_line *mail_headers;
  uschar *dcc_acl_options;
  gstring *dcc_xtra_hdrs;
  gstring *dcc_header_str;

  /* grep 1st option */
  if ((dcc_acl_options = string_nextinlist(&list, &sep, NULL, 0))) {
    /* parse 1st option */
    if (  strcmpic(dcc_acl_options, US"false") == 0
       || Ustrcmp(dcc_acl_options, "0") == 0)
      return FAIL;	/* explicitly no matching */
  }
  else
    return FAIL;	/* empty means "don't match anything" */

  sep = 0;

  /* if we scanned this message last time, just return */
  if (dcc_ok)
    return dcc_rc;

  /* open the spooled body */
  for (int i = 0; i < 2; i++) {
    uschar message_subdir[2];
    set_subdir_str(message_subdir, message_id, i);
    if ((data_file = Ufopen(
	    spool_fname(US"input", message_subdir, message_id, US"-D"), "rb")))
      break;
  }

  if (!data_file) {
    /* error while spooling */
    log_write(0, LOG_MAIN|LOG_PANIC,
           "DCC: error while opening spool file");
    return DEFER;
  }

  /* Initialize the variables */

  bzero(sockip,sizeof(sockip));
  if (dccifd_address) {
    if (dccifd_address[0] == '/')
      Ustrncpy(sockpath, dccifd_address, sizeof(sockpath));
    else
      if( sscanf(CS dccifd_address, "%s %u", sockip, &portnr) != 2) {
        log_write(0, LOG_MAIN,
          "DCC: warning - invalid dccifd address: '%s'", dccifd_address);
        (void)fclose(data_file);
        return DEFER;
      }
  }

  /* dcc_headers is what we send as dccifd options - see man dccifd */
  /* We don't support any other option than 'header' so just copy that */
  dcc_headers = string_cat(NULL, dccifd_options);
  /* if $acl_m_dcc_override_client_ip is set use it */
  if (((override_client_ip = expand_string(US"$acl_m_dcc_override_client_ip")) != NULL) &&
       (override_client_ip[0] != '\0')) {
    Ustrncpy(client_ip, override_client_ip, sizeof(client_ip)-1);
    DEBUG(D_acl)
      debug_printf("DCC: Client IP (overridden): %s\n", client_ip);
  }
  else if(sender_host_address) {
  /* else if $sender_host_address is available use that? */
    Ustrncpy(client_ip, sender_host_address, sizeof(client_ip)-1);
    DEBUG(D_acl)
      debug_printf("DCC: Client IP (sender_host_address): %s\n", client_ip);
  }
  else {
    /* sender_host_address is NULL which means it comes from localhost */
    Ustrncpy(client_ip, dcc_default_ip_option, sizeof(client_ip)-1);
    DEBUG(D_acl)
      debug_printf("DCC: Client IP (default): %s\n", client_ip);
  }
  /* build options block */
  dcc_headers = string_append(dcc_headers, 5, US"\n", client_ip, US"\nHELO ", dcc_helo_option, US"\n");

  /* initialize the other variables */
  mail_headers = header_list;
  /* we set the default return value to DEFER */
  retval = DEFER;

  /* send a null return path as "<>". */
  dcc_headers = string_cat (dcc_headers, *sender_address ? sender_address : US"<>");
  dcc_headers = string_catn(dcc_headers, US"\n", 1);

  /**************************************
   * Now creating the socket connection *
   **************************************/

  /* If sockip contains an ip, we use a tcp socket, otherwise a UNIX socket */
  if(Ustrcmp(sockip, "")) {
    ipaddress = gethostbyname(CS sockip);
    bzero(CS  &serv_addr_in, sizeof(serv_addr_in));
    serv_addr_in.sin_family = AF_INET;
    bcopy(CS ipaddress->h_addr, CS &serv_addr_in.sin_addr.s_addr, ipaddress->h_length);
    serv_addr_in.sin_port = htons(portnr);
    if ((sockfd = socket(AF_INET, SOCK_STREAM,0)) < 0) {
      DEBUG(D_acl)
        debug_printf("DCC: Creating TCP socket connection failed: %s\n", strerror(errno));
      log_write(0,LOG_PANIC,"DCC: Creating TCP socket connection failed: %s\n", strerror(errno));
      /* if we cannot create the socket, defer the mail */
      (void)fclose(data_file);
      return retval;
    }
    /* Now connecting the socket (INET) */
    if (connect(sockfd, (struct sockaddr *)&serv_addr_in, sizeof(serv_addr_in)) < 0) {
      DEBUG(D_acl)
        debug_printf("DCC: Connecting to TCP socket failed: %s\n", strerror(errno));
      log_write(0,LOG_PANIC,"DCC: Connecting to TCP socket failed: %s\n", strerror(errno));
      /* if we cannot contact the socket, defer the mail */
      (void)fclose(data_file);
      return retval;
    }
  }
  else {
    /* connecting to the dccifd UNIX socket */
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sun_family = AF_UNIX;
    Ustrncpy(US serv_addr.sun_path, sockpath, sizeof(serv_addr.sun_path));
    if ((sockfd = socket(AF_UNIX, SOCK_STREAM,0)) < 0) {
      DEBUG(D_acl)
        debug_printf("DCC: Creating UNIX socket connection failed: %s\n", strerror(errno));
      log_write(0,LOG_PANIC,"DCC: Creating UNIX socket connection failed: %s\n", strerror(errno));
      /* if we cannot create the socket, defer the mail */
      (void)fclose(data_file);
      return retval;
    }
    /* Now connecting the socket (UNIX) */
    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
      DEBUG(D_acl)
        debug_printf("DCC: Connecting to UNIX socket failed: %s\n", strerror(errno));
      log_write(0,LOG_PANIC,"DCC: Connecting to UNIX socket failed: %s\n", strerror(errno));
      /* if we cannot contact the socket, defer the mail */
      (void)fclose(data_file);
      return retval;
    }
  }
  /* the socket is open, now send the options to dccifd*/
  DEBUG(D_acl)
    debug_printf("DCC: -----------------------------------\nDCC: Socket opened; now sending input\n"
                 "DCC: -----------------------------------\n");

  /* let's send each of the recipients to dccifd */
  for (int i = 0; i < recipients_count; i++) {
    DEBUG(D_acl)
      debug_printf("DCC: recipient = %s\n",recipients_list[i].address);
    dcc_headers = string_append(dcc_headers, 2, recipients_list[i].address, "\n");
  }
  /* send a blank line between options and message */
  dcc_headers = string_catn(dcc_headers, US"\n", 1);
  /* Now we send the input buffer */
  (void) string_from_gstring(dcc_headers);
  DEBUG(D_acl)
    debug_printf("DCC: ***********************************\nDCC: Sending options:\n%s"
                 "DCC: ***********************************\n", dcc_headers->s);
  if (flushbuffer(sockfd, dcc_headers) != 0) {
      (void)fclose(data_file);
      return retval;
  }

  /* now send the message */
  /* First send the headers */
  DEBUG(D_acl)
    debug_printf("DCC: ***********************************\nDCC: Sending headers:\n");
  sendbuf = string_get(8192);
  sendbuf = string_catn(sendbuf, mail_headers->text, mail_headers->slen);
  while((mail_headers=mail_headers->next)) {
    sendbuf = string_catn(sendbuf, mail_headers->text, mail_headers->slen);
  }

  /* a blank line separates header from body */
  sendbuf = string_catn(sendbuf, US"\r\n", 2);
  (void) string_from_gstring(sendbuf);
  gstring_release_unused(sendbuf);
  DEBUG(D_acl)
    debug_printf("%sDCC: ***********************************\n", sendbuf->s);
  if (flushbuffer(sockfd, sendbuf) != 0) {
      (void)fclose(data_file);
      return retval;
  }

  /* now send the body */
  DEBUG(D_acl)
    debug_printf("DCC: ***********************************\nDCC: Writing body:\n");
  (void)fseek(data_file, SPOOL_DATA_START_OFFSET, SEEK_SET);

  gstring filebuf = { .size = big_buffer_size, .ptr = 0, .s = big_buffer };

  while((filebuf.ptr = fread(filebuf.s, 1, filebuf.size, data_file)) > 0) {
    if (flushbuffer(sockfd, &filebuf) != 0) {
        (void)fclose(data_file);
        return retval;
    }
  }
  DEBUG(D_acl)
    debug_printf("DCC: ***********************************\n");

  /* shutdown() the socket */
  if(shutdown(sockfd, SHUT_WR) < 0) {
    DEBUG(D_acl)
      debug_printf("DCC: Couldn't shutdown socket: %s\n", strerror(errno));
    log_write(0,LOG_MAIN,"DCC: Couldn't shutdown socket: %s\n", strerror(errno));
    /* If there is a problem with the shutdown()
     * defer the mail. */
    (void)fclose(data_file);
    return retval;
  }
  DEBUG(D_acl)
    debug_printf("DCC: Input sent.\n"
                 "DCC: +++++++++++++++++++++++++++++++++++\n"
                 "DCC: Now receiving output from server\n"
                 "DCC: -----------------------------------\n");

  /********************************
   * receiving output from dccifd *
   ********************************/

  /******************************************************************
   * We should get 3 lines:                                         *
   * 1/ First line is overall result: either 'A' for Accept,        *
   *    'R' for Reject, 'S' for accept Some recipients or           *
   *    'T' for a Temporary error.                                  *
   * 2/ Second line contains the list of Accepted/Rejected          *
   *    recipients in the form AARRA (A = accepted, R = rejected).  *
   * 3/ Third line contains the X-DCC header.                       *
   ******************************************************************/

  int line = 1;    /* we start at the first line of the output */
  int bufoffset;

  dcc_header_str = string_get(DCC_HEADER_LIMIT + 2);
  /* Let's read from the socket until there's nothing left to read */
  while((dcc_resplen = read(sockfd, big_buffer, big_buffer_size-1)) > 0) {
    /* fail on read error */
    if(dcc_resplen < 0) {
      DEBUG(D_acl)
        debug_printf("DCC: Error reading from socket: %s\n", strerror(errno));
      (void)fclose(data_file);
      return retval;
    }
    /* make the answer 0-terminated. only needed for debug_printf */
    DEBUG(D_acl)
      debug_printf("DCC: Length of the output buffer is: %d\nDCC: Output buffer is:\n"
                   "DCC: -----------------------------------\n%.*s\n"
                   "DCC: -----------------------------------\n", dcc_resplen, dcc_resplen, big_buffer);

    /* Now let's read each character and see what we've got */
    for(bufoffset = 0; bufoffset < dcc_resplen, line <= 2; bufoffset++) {
      /* First check if we reached the end of the line and
       * then increment the line counter */
      if(big_buffer[bufoffset] == '\n')
        line++;
      else {
        /* The first character of the first line is the
         * overall response. If there's another character
         * on that line it is not correct. */
        if(line == 1) {
          if(bufoffset == 0) {
            /* Now get the value and set the
             * return value accordingly */
            switch(big_buffer[bufoffset]) {
              case 'A':
                DEBUG(D_acl)
                  debug_printf("DCC: Overall result = A\treturning OK\n");
                dcc_return_text = US"Mail accepted by DCC";
                dcc_result = US"A";
                retval = OK;
                break;
              case 'R':
                DEBUG(D_acl)
                  debug_printf("DCC: Overall result = R\treturning FAIL\n");
                dcc_return_text = US"Rejected by DCC";
                dcc_result = US"R";
                retval = FAIL;
                if(sender_host_name)
                  log_write(0, LOG_MAIN, "H=%s [%s] F=<%s>: rejected by DCC",
                             sender_host_name, sender_host_address, sender_address);
                else
                  log_write(0, LOG_MAIN, "H=[%s] F=<%s>: rejected by DCC",
                             sender_host_address, sender_address);
                break;
              case 'S':
                DEBUG(D_acl)
                  debug_printf("DCC: Overall result  = S\treturning OK\n");
                dcc_return_text = US"Not all recipients accepted by DCC";
                /* Since we're in an ACL we want a global result
                 * so we accept for all */
                dcc_result = US"A";
                retval = OK;
                break;
              case 'G':
                DEBUG(D_acl)
                  debug_printf("DCC: Overall result  = G\treturning FAIL\n");
                dcc_return_text = US"Greylisted by DCC";
                dcc_result = US"G";
                retval = FAIL;
                break;
              case 'T':
                DEBUG(D_acl)
                  debug_printf("DCC: Overall result = T\treturning DEFER\n");
                dcc_return_text = US"Temporary error with DCC";
                dcc_result = US"T";
                retval = DEFER;
                log_write(0,LOG_MAIN,"Temporary error with DCC: %s\n", big_buffer);
                break;
              default:
                DEBUG(D_acl)
                  debug_printf("DCC: Overall result = something else\treturning DEFER\n");
		dcc_return_text = US"Unknown DCC response";
                dcc_result = US"T";
                retval = DEFER;
                log_write(0,LOG_MAIN,"Unknown DCC response: %s\n", big_buffer);
                break;
            }
          }
          else {
            /* We're on the first line but not on the first character,
             * there must be something wrong. */
            DEBUG(D_acl) debug_printf("DCC: Line = %d but bufoffset = %d != 0"
		"  character is %c - This is wrong!\n", line, bufoffset, big_buffer[bufoffset]);
            log_write(0,LOG_MAIN,"Wrong header from DCC, output is %s\n", big_buffer);
          }
        }
        else if(line == 2) {
          /* On the second line we get a list of
           * answers for each recipient. We don't care about
           * it because we're in an acl and take the
           * global result. */
        }
      }
    }
    if(line > 2) {
      /* The third and following lines are the X-DCC header,
       * so we store it in dcc_header_str up to our limit. */
      /* check if buffer contains the end of the header .."\n\n" and truncate it */
      if ((big_buffer[dcc_resplen-1] == '\n') &&
          (big_buffer[dcc_resplen-2] == '\n'))
        dcc_resplen -= 2;
      dcc_resplen -= bufoffset;
      if (dcc_header_str->ptr + dcc_resplen > DCC_HEADER_LIMIT) {
        dcc_resplen = DCC_HEADER_LIMIT - dcc_header_str->ptr;
        DEBUG(D_acl) debug_printf("DCC: We got more output than we can store"
	                   "in the X-DCC header. Truncating at 120 characters.\n");
      }
      dcc_header_str = string_catn(dcc_header_str, &big_buffer[bufoffset], dcc_resplen);
    }
  }
  /* We have read everything from the socket. make sure the header ends with "\n" */
  dcc_header_str = string_catn(dcc_header_str, US"\n", 1);

  (void) string_from_gstring(dcc_header_str);
  /* Now let's sum up what we've got. */
  DEBUG(D_acl)
    debug_printf("\nDCC: --------------------------\nDCC: Overall result = %d\n"
                 "DCC: X-DCC header: %sReturn message: %s\nDCC: dcc_result: %s\n",
                   retval, dcc_header_str->s, dcc_return_text, dcc_result);

  /* We only add the X-DCC header if it starts with X-DCC */
  if(!(Ustrncmp(dcc_header_str->s, "X-DCC", 5))) {
    dcc_header = dcc_header_str->s;
    if(dcc_direct_add_header) {
      header_add(' ' , "%s", dcc_header_str->s);
  /* since the MIME ACL already writes the .eml file to disk without DCC Header we've to erase it */
      unspool_mbox();
    }
  }
  else {
    DEBUG(D_acl)
      debug_printf("DCC: Wrong format of the X-DCC header: %.*s\n", dcc_header_str->ptr, dcc_header_str->s);
  }

  /* check if we should add additional headers passed in acl_m_dcc_add_header */
  if(dcc_direct_add_header) {
    if (((xtra_hdrs = expand_string(US"$acl_m_dcc_add_header")) != NULL) && (xtra_hdrs[0] != '\0')) {
      dcc_xtra_hdrs = string_cat(NULL, xtra_hdrs);
      if (dcc_xtra_hdrs->s[dcc_xtra_hdrs->ptr - 1] != '\n')
        dcc_xtra_hdrs = string_catn(dcc_xtra_hdrs, US"\n", 1);
      header_add(' ', "%s", string_from_gstring(dcc_xtra_hdrs));
      DEBUG(D_acl)
        debug_printf("DCC: adding additional headers in $acl_m_dcc_add_header: %.*s", dcc_xtra_hdrs->ptr, dcc_xtra_hdrs->s);
    }
  }

  dcc_ok = 1;
  /* Now return to exim main process */
  DEBUG(D_acl)
    debug_printf("DCC: Before returning to exim main process:\nDCC: return_text = %s - retval = %d\n"
                 "DCC: dcc_result = %s\n", dcc_return_text, retval, dcc_result);

  (void)fclose(data_file);
  dcc_rc = retval;
  return dcc_rc;
}

#endif
