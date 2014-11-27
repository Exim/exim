/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Tom Kistner <tom@duncanthrax.net> 2003-???? */
/* License: GPL */

/* Code for calling spamassassin's spamd. Called from acl.c. */

#include "exim.h"
#ifdef WITH_CONTENT_SCAN
#include "spam.h"

uschar spam_score_buffer[16];
uschar spam_score_int_buffer[16];
uschar spam_bar_buffer[128];
uschar spam_report_buffer[32600];
uschar prev_user_name[128] = "";
int spam_ok = 0;
int spam_rc = 0;
uschar *prev_spamd_address_work = NULL;

int
spam(uschar **listptr)
{
  int sep = 0;
  uschar *list = *listptr;
  uschar *user_name;
  uschar user_name_buffer[128];
  unsigned long mbox_size;
  FILE *mbox_file;
  int spamd_sock = -1;
  uschar spamd_buffer[32600];
  int i, j, offset, result;
  uschar spamd_version[8];
  uschar spamd_score_char;
  double spamd_threshold, spamd_score;
  int spamd_report_offset;
  uschar *p,*q;
  int override = 0;
  time_t start;
  size_t read, wrote;
  struct sockaddr_un server;
#ifndef NO_POLL_H
  struct pollfd pollfd;
#else                               /* Patch posted by Erik ? for OS X */
  struct timeval select_tv;         /* and applied by PH */
  fd_set select_fd;
#endif
  uschar *spamd_address_work;

  /* stop compiler warning */
  result = 0;

  /* find the username from the option list */
  if ((user_name = string_nextinlist(&list, &sep,
                                     user_name_buffer,
                                     sizeof(user_name_buffer))) == NULL)
    {
    /* no username given, this means no scanning should be done */
    return FAIL;
    }

  /* if username is "0" or "false", do not scan */
  if ( (Ustrcmp(user_name,"0") == 0) ||
       (strcmpic(user_name,US"false") == 0) )
    return FAIL;

  /* if there is an additional option, check if it is "true" */
  if (strcmpic(list,US"true") == 0)
    /* in that case, always return true later */
    override = 1;

  /* expand spamd_address if needed */
  if (*spamd_address == '$')
    {
    spamd_address_work = expand_string(spamd_address);
    if (spamd_address_work == NULL)
      {
      log_write(0, LOG_MAIN|LOG_PANIC,
        "spamassassin acl condition: spamd_address starts with $, but expansion failed: %s", expand_string_message);
      return DEFER;
      }
    }
  else
    spamd_address_work = spamd_address;

  /* check if previous spamd_address was expanded and has changed. dump cached results if so */
  if (  spam_ok
     && prev_spamd_address_work != NULL
     && Ustrcmp(prev_spamd_address_work, spamd_address_work) != 0
     )
    spam_ok = 0;

  /* if we scanned for this username last time, just return */
  if ( spam_ok && Ustrcmp(prev_user_name, user_name) == 0)
    if (override)
      return OK;
    else
      return spam_rc;

  /* make sure the eml mbox file is spooled up */
  mbox_file = spool_mbox(&mbox_size, NULL);

  if (mbox_file == NULL)
    {
    /* error while spooling */
    log_write(0, LOG_MAIN|LOG_PANIC,
           "spam acl condition: error while creating mbox spool file");
    return DEFER;
    }

  start = time(NULL);

  /* socket does not start with '/' -> network socket */
  if (*spamd_address_work != '/')
    {
    int num_servers = 0;
    int current_server;
    uschar *address = NULL;
    uschar *spamd_address_list_ptr = spamd_address_work;
    uschar address_buffer[256];
    spamd_address_container * spamd_address_vector[32];

    /* Check how many spamd servers we have
       and register their addresses */
    while ((address = string_nextinlist(&spamd_address_list_ptr, &sep,
                                        address_buffer,
                                        sizeof(address_buffer))) != NULL)
      {

      /* Potential memory leak as we never free the store. */
      spamd_address_container *this_spamd =
        (spamd_address_container *)store_get(sizeof(spamd_address_container));

      /* grok spamd address and port */
      if (sscanf(CS address, "%23s %u", this_spamd->tcp_addr, &(this_spamd->tcp_port)) != 2)
        {
        log_write(0, LOG_MAIN,
          "spam acl condition: warning - invalid spamd address: '%s'", address);
        continue;
	}

      spamd_address_vector[num_servers] = this_spamd;
      if (++num_servers > 31)
        break;
      }

    /* check if we have at least one server */
    if (!num_servers)
      {
      log_write(0, LOG_MAIN|LOG_PANIC,
         "spam acl condition: no useable spamd server addresses in spamd_address configuration option.");
      (void)fclose(mbox_file);
      return DEFER;
      }

    while ( num_servers > 0 )
      {
      int i;

      /* Randomly pick a server to try */
      current_server = random_number( num_servers );

      debug_printf("trying server %s, port %u\n",
                   spamd_address_vector[current_server]->tcp_addr,
                   spamd_address_vector[current_server]->tcp_port);

      /* contact a spamd */
      if ( (spamd_sock = ip_socket(SOCK_STREAM, AF_INET)) < 0)
	{
        log_write(0, LOG_MAIN|LOG_PANIC,
           "spam acl condition: error creating IP socket for spamd");
        (void)fclose(mbox_file);
        return DEFER;
	}

      if (ip_connect( spamd_sock,
                      AF_INET,
                      spamd_address_vector[current_server]->tcp_addr,
                      spamd_address_vector[current_server]->tcp_port,
                      5 ) > -1)
        /* connection OK */
        break;

      log_write(0, LOG_MAIN|LOG_PANIC,
         "spam acl condition: warning - spamd connection to %s, port %u failed: %s",
         spamd_address_vector[current_server]->tcp_addr,
         spamd_address_vector[current_server]->tcp_port,
         strerror(errno));

      (void)close(spamd_sock);

      /* Remove the server from the list. XXX We should free the memory */
      num_servers--;
      for ( i = current_server; i < num_servers; i++ )
        spamd_address_vector[i] = spamd_address_vector[i+1];
      }

    if ( num_servers == 0 )
      {
      log_write(0, LOG_MAIN|LOG_PANIC, "spam acl condition: all spamd servers failed");
      (void)fclose(mbox_file);
      return DEFER;
      }
    }
  else
    {
    /* open the local socket */

    if ((spamd_sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
      {
      log_write(0, LOG_MAIN|LOG_PANIC,
                "malware acl condition: spamd: unable to acquire socket (%s)",
                strerror(errno));
      (void)fclose(mbox_file);
      return DEFER;
      }

    server.sun_family = AF_UNIX;
    Ustrcpy(server.sun_path, spamd_address_work);

    if (connect(spamd_sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0)
      {
      log_write(0, LOG_MAIN|LOG_PANIC,
                "malware acl condition: spamd: unable to connect to UNIX socket %s (%s)",
                spamd_address_work, strerror(errno) );
      (void)fclose(mbox_file);
      (void)close(spamd_sock);
      return DEFER;
      }
    }

  if (spamd_sock == -1)
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
        "programming fault, spamd_sock unexpectedly unset");
    (void)fclose(mbox_file);
    (void)close(spamd_sock);
    return DEFER;
    }

  /* now we are connected to spamd on spamd_sock */
  (void)string_format(spamd_buffer,
           sizeof(spamd_buffer),
           "REPORT SPAMC/1.2\r\nUser: %s\r\nContent-length: %ld\r\n\r\n",
           user_name,
           mbox_size);

  /* send our request */
  if (send(spamd_sock, spamd_buffer, Ustrlen(spamd_buffer), 0) < 0)
    {
    (void)close(spamd_sock);
    log_write(0, LOG_MAIN|LOG_PANIC,
         "spam acl condition: spamd send failed: %s", strerror(errno));
    (void)fclose(mbox_file);
    (void)close(spamd_sock);
    return DEFER;
    }

  /* now send the file */
  /* spamd sometimes accepts conections but doesn't read data off
   * the connection.  We make the file descriptor non-blocking so
   * that the write will only write sufficient data without blocking
   * and we poll the desciptor to make sure that we can write without
   * blocking.  Short writes are gracefully handled and if the whole
   * trasaction takes too long it is aborted.
   * Note: poll() is not supported in OSX 10.2 and is reported to be
   *       broken in more recent versions (up to 10.4).
   */
#ifndef NO_POLL_H
  pollfd.fd = spamd_sock;
  pollfd.events = POLLOUT;
#endif
  (void)fcntl(spamd_sock, F_SETFL, O_NONBLOCK);
  do
    {
    read = fread(spamd_buffer,1,sizeof(spamd_buffer),mbox_file);
    if (read > 0)
      {
      offset = 0;
again:
#ifndef NO_POLL_H
      result = poll(&pollfd, 1, 1000);

/* Patch posted by Erik ? for OS X and applied by PH */
#else
      select_tv.tv_sec = 1;
      select_tv.tv_usec = 0;
      FD_ZERO(&select_fd);
      FD_SET(spamd_sock, &select_fd);
      result = select(spamd_sock+1, NULL, &select_fd, NULL, &select_tv);
#endif
/* End Erik's patch */

      if (result == -1 && errno == EINTR)
        goto again;
      else if (result < 1)
	{
        if (result == -1)
          log_write(0, LOG_MAIN|LOG_PANIC,
            "spam acl condition: %s on spamd socket", strerror(errno));
        else
	  {
          if (time(NULL) - start < SPAMD_TIMEOUT)
            goto again;
          log_write(0, LOG_MAIN|LOG_PANIC,
            "spam acl condition: timed out writing spamd socket");
	  }
        (void)close(spamd_sock);
        (void)fclose(mbox_file);
        return DEFER;
	}

      wrote = send(spamd_sock,spamd_buffer + offset,read - offset,0);
      if (wrote == -1)
	{
	log_write(0, LOG_MAIN|LOG_PANIC,
            "spam acl condition: %s on spamd socket", strerror(errno));
        (void)close(spamd_sock);
        (void)fclose(mbox_file);
        return DEFER;
	}
      if (offset + wrote != read)
	{
        offset += wrote;
        goto again;
	}
      }
    }
  while (!feof(mbox_file) && !ferror(mbox_file));

  if (ferror(mbox_file))
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
      "spam acl condition: error reading spool file: %s", strerror(errno));
    (void)close(spamd_sock);
    (void)fclose(mbox_file);
    return DEFER;
    }

  (void)fclose(mbox_file);

  /* we're done sending, close socket for writing */
  shutdown(spamd_sock,SHUT_WR);

  /* read spamd response using what's left of the timeout.
   */
  memset(spamd_buffer, 0, sizeof(spamd_buffer));
  offset = 0;
  while ((i = ip_recv(spamd_sock,
                     spamd_buffer + offset,
                     sizeof(spamd_buffer) - offset - 1,
                     SPAMD_TIMEOUT - time(NULL) + start)) > 0 )
    offset += i;

  /* error handling */
  if (i <= 0 && errno != 0)
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
         "spam acl condition: error reading from spamd socket: %s", strerror(errno));
    (void)close(spamd_sock);
    return DEFER;
    }

  /* reading done */
  (void)close(spamd_sock);

  /* dig in the spamd output and put the report in a multiline header, if requested */
  if (sscanf(CS spamd_buffer,
	      "SPAMD/%7s 0 EX_OK\r\nContent-length: %*u\r\n\r\n%lf/%lf\r\n%n",
	      spamd_version, &spamd_score, &spamd_threshold,
	      &spamd_report_offset) != 3)
    {

    /* try to fall back to pre-2.50 spamd output */
    if (sscanf(CS spamd_buffer,
		"SPAMD/%7s 0 EX_OK\r\nSpam: %*s ; %lf / %lf\r\n\r\n%n",
                spamd_version, &spamd_score, &spamd_threshold,
		&spamd_report_offset) != 3 )
      {
      log_write(0, LOG_MAIN|LOG_PANIC,
         "spam acl condition: cannot parse spamd output");
      return DEFER;
      }
    }

  /* Create report. Since this is a multiline string,
  we must hack it into shape first */
  p = &spamd_buffer[spamd_report_offset];
  q = spam_report_buffer;
  while (*p != '\0')
    {
    /* skip \r */
    if (*p == '\r')
      {
      p++;
      continue;
      }
    *q++ = *p;
    if (*p++ == '\n')
      {
      /* add an extra space after the newline to ensure
      that it is treated as a header continuation line */
      *q++ = ' ';
      }
    }
  /* NULL-terminate */
  *q-- = '\0';
  /* cut off trailing leftovers */
  while (*q <= ' ')
    *q-- = '\0';

  spam_report = spam_report_buffer;

  /* create spam bar */
  spamd_score_char = spamd_score > 0 ? '+' : '-';
  j = abs((int)(spamd_score));
  i = 0;
  if (j != 0)
    while ((i < j) && (i <= MAX_SPAM_BAR_CHARS))
       spam_bar_buffer[i++] = spamd_score_char;
  else
    {
    spam_bar_buffer[0] = '/';
    i = 1;
    }
  spam_bar_buffer[i] = '\0';
  spam_bar = spam_bar_buffer;

  /* create "float" spam score */
  (void)string_format(spam_score_buffer, sizeof(spam_score_buffer),"%.1f", spamd_score);
  spam_score = spam_score_buffer;

  /* create "int" spam score */
  j = (int)((spamd_score + 0.001)*10);
  (void)string_format(spam_score_int_buffer, sizeof(spam_score_int_buffer), "%d", j);
  spam_score_int = spam_score_int_buffer;

  /* compare threshold against score */
  if (spamd_score >= spamd_threshold)
    {
    /* spam as determined by user's threshold */
    spam_rc = OK;
    }
  else
    {
    /* not spam */
    spam_rc = FAIL;
    }

  /* remember expanded spamd_address if needed */
  if (spamd_address_work != spamd_address)
    prev_spamd_address_work = string_copy(spamd_address_work);

  /* remember user name and "been here" for it */
  Ustrcpy(prev_user_name, user_name);
  spam_ok = 1;

  if (override) /* always return OK, no matter what the score */
    return OK;
  else
    return spam_rc;
}

#endif
