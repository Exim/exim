/* $Cambridge: exim/src/src/spam.c,v 1.1.2.3 2004/11/30 15:18:58 tom Exp $ */

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

int spam(uschar **listptr) {
  int sep = 0;
  uschar *list = *listptr;
  uschar *user_name;
  uschar user_name_buffer[128];
  unsigned long long mbox_size;
  FILE *mbox_file;
  int spamd_sock;
  uschar spamd_buffer[32600];
  int i, j, offset;
  uschar spamd_version[8];
  uschar spamd_score_char;
  double spamd_threshold, spamd_score;
  int spamd_report_offset;
  uschar *p,*q;
  int override = 0;
  struct sockaddr_un server;

  /* find the username from the option list */
  if ((user_name = string_nextinlist(&list, &sep,
                                     user_name_buffer,
                                     sizeof(user_name_buffer))) == NULL) {
    /* no username given, this means no scanning should be done */
    return FAIL;
  };

  /* if username is "0" or "false", do not scan */
  if ( (Ustrcmp(user_name,"0") == 0) ||
       (strcmpic(user_name,US"false") == 0) ) {
    return FAIL;
  };

  /* if there is an additional option, check if it is "true" */
  if (strcmpic(list,US"true") == 0) {
    /* in that case, always return true later */
    override = 1;
  };

  /* if we scanned for this username last time, just return */ 
  if ( spam_ok && ( Ustrcmp(prev_user_name, user_name) == 0 ) ) {
    if (override)
      return OK;
    else
      return spam_rc;
  };
  
  /* make sure the eml mbox file is spooled up */
  mbox_file = spool_mbox(&mbox_size);
  
  if (mbox_file == NULL) {
    /* error while spooling */
    log_write(0, LOG_MAIN|LOG_PANIC,
           "spam acl condition: error while creating mbox spool file");
    return DEFER;
  };

  /* socket does not start with '/' -> network socket */
  if (*spamd_address != '/') {
    time_t now = time(NULL);
    int num_servers = 0;
    int current_server = 0;
    int start_server = 0;
    uschar *address = NULL;
    uschar *spamd_address_list_ptr = spamd_address;
    uschar address_buffer[256];
    spamd_address_container * spamd_address_vector[32];

    /* Check how many spamd servers we have
       and register their addresses */
    while ((address = string_nextinlist(&spamd_address_list_ptr, &sep,
                                        address_buffer,
                                        sizeof(address_buffer))) != NULL) {
      
      spamd_address_container *this_spamd =
        (spamd_address_container *)store_get(sizeof(spamd_address_container));
      
      /* grok spamd address and port */
      if( sscanf(CS address, "%s %u", this_spamd->tcp_addr, &(this_spamd->tcp_port)) != 2 ) {
        log_write(0, LOG_MAIN,
          "spam acl condition: warning - invalid spamd address: '%s'", address);
        continue;
      };
      
      spamd_address_vector[num_servers] = this_spamd;
      num_servers++;
      if (num_servers > 31)
        break;
    };
    
    /* check if we have at least one server */
    if (!num_servers) {
      log_write(0, LOG_MAIN|LOG_PANIC,
         "spam acl condition: no useable spamd server addresses in spamd_address configuration option.");
      fclose(mbox_file);
      return DEFER;
    };

    current_server = start_server = (int)now % num_servers;

    while (1) {
      
      debug_printf("trying server %s, port %u\n",
                   spamd_address_vector[current_server]->tcp_addr,
                   spamd_address_vector[current_server]->tcp_port);
      
      /* contact a spamd */
      if ( (spamd_sock = ip_socket(SOCK_STREAM, AF_INET)) < 0) {
        log_write(0, LOG_MAIN|LOG_PANIC,
           "spam acl condition: error creating IP socket for spamd");
        fclose(mbox_file);
        return DEFER; 
      };
      
      if (ip_connect( spamd_sock,
                      AF_INET,
                      spamd_address_vector[current_server]->tcp_addr,
                      spamd_address_vector[current_server]->tcp_port,
                      5 ) > -1) {
        /* connection OK */
        break;
      };
      
      log_write(0, LOG_MAIN|LOG_PANIC,
         "spam acl condition: warning - spamd connection to %s, port %u failed: %s",
         spamd_address_vector[current_server]->tcp_addr,
         spamd_address_vector[current_server]->tcp_port,
         strerror(errno));
      current_server++;
      if (current_server >= num_servers)
        current_server = 0;
      if (current_server == start_server) {
        log_write(0, LOG_MAIN|LOG_PANIC, "spam acl condition: all spamd servers failed");
        fclose(mbox_file);
        close(spamd_sock);
        return DEFER;
      };
    };

  }
  else {
    /* open the local socket */

    if ((spamd_sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
      log_write(0, LOG_MAIN|LOG_PANIC,
                "malware acl condition: spamd: unable to acquire socket (%s)",
                strerror(errno));
      fclose(mbox_file);
      return DEFER;
    }

    server.sun_family = AF_UNIX;
    Ustrcpy(server.sun_path, spamd_address);

    if (connect(spamd_sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0) {
      log_write(0, LOG_MAIN|LOG_PANIC,
                "malware acl condition: spamd: unable to connect to UNIX socket %s (%s)",
                spamd_address, strerror(errno) );
      fclose(mbox_file);
      close(spamd_sock);
      return DEFER;
    }

  }

  /* now we are connected to spamd on spamd_sock */
  snprintf(CS spamd_buffer,
           sizeof(spamd_buffer),
           "REPORT SPAMC/1.2\r\nUser: %s\r\nContent-length: %lld\r\n\r\n",
           user_name,
           mbox_size);

  /* send our request */
  if (send(spamd_sock, spamd_buffer, Ustrlen(spamd_buffer), 0) < 0) {
    close(spamd_sock);
    log_write(0, LOG_MAIN|LOG_PANIC,
         "spam acl condition: spamd send failed: %s", strerror(errno));
    fclose(mbox_file);
    close(spamd_sock);
    return DEFER;
  };

  /* now send the file */
  do {
    j = fread(spamd_buffer,1,sizeof(spamd_buffer),mbox_file);
    if (j > 0) {
      i = send(spamd_sock,spamd_buffer,j,0);
      if (i != j) {
        log_write(0, LOG_MAIN|LOG_PANIC,
          "spam acl condition: error/short send to spamd");
        close(spamd_sock);
        fclose(mbox_file);
        return DEFER;
      };
    };
  }
  while (j > 0);

  fclose(mbox_file);

  /* we're done sending, close socket for writing */
  shutdown(spamd_sock,SHUT_WR);
  
  /* read spamd response */
  memset(spamd_buffer, 0, sizeof(spamd_buffer));
  offset = 0;
  while((i = ip_recv(spamd_sock,
                     spamd_buffer + offset,
                     sizeof(spamd_buffer) - offset - 1,
                     SPAMD_READ_TIMEOUT)) > 0 ) {
    offset += i;
  }

  /* error handling */
  if((i <= 0) && (errno != 0)) {
    log_write(0, LOG_MAIN|LOG_PANIC,
         "spam acl condition: error reading from spamd socket: %s", strerror(errno));
    close(spamd_sock);
    return DEFER;
  }

  /* reading done */
  close(spamd_sock);

  /* dig in the spamd output and put the report in a multiline header, if requested */
  if( sscanf(CS spamd_buffer,"SPAMD/%s 0 EX_OK\r\nContent-length: %*u\r\n\r\n%lf/%lf\r\n%n",
             spamd_version,&spamd_score,&spamd_threshold,&spamd_report_offset) != 3 ) {
              
    /* try to fall back to pre-2.50 spamd output */
    if( sscanf(CS spamd_buffer,"SPAMD/%s 0 EX_OK\r\nSpam: %*s ; %lf / %lf\r\n\r\n%n",
               spamd_version,&spamd_score,&spamd_threshold,&spamd_report_offset) != 3 ) {
      log_write(0, LOG_MAIN|LOG_PANIC,
         "spam acl condition: cannot parse spamd output");
      return DEFER;
    };
  };

  /* Create report. Since this is a multiline string,
  we must hack it into shape first */
  p = &spamd_buffer[spamd_report_offset];
  q = spam_report_buffer;
  while (*p != '\0') {
    /* skip \r */
    if (*p == '\r') {
      p++;
      continue;
    };
    *q = *p;
    q++;
    if (*p == '\n') {
      *q = '\t';
      q++;
      /* eat whitespace */
      while( (*p <= ' ') && (*p != '\0') ) {
        p++;
      };
      p--;
    };
    p++;
  };
  /* NULL-terminate */
  *q = '\0';
  q--;
  /* cut off trailing leftovers */
  while (*q <= ' ') {
    *q = '\0';
    q--;
  };
  spam_report = spam_report_buffer;

  /* create spam bar */
  spamd_score_char = spamd_score > 0 ? '+' : '-';
  j = abs((int)(spamd_score));
  i = 0;
  if( j != 0 ) {
    while((i < j) && (i <= MAX_SPAM_BAR_CHARS))
       spam_bar_buffer[i++] = spamd_score_char;
  }
  else{
    spam_bar_buffer[0] = '/';
    i = 1;
  }
  spam_bar_buffer[i] = '\0';
  spam_bar = spam_bar_buffer;

  /* create "float" spam score */
  snprintf(CS spam_score_buffer, sizeof(spam_score_buffer),"%.1f", spamd_score);
  spam_score = spam_score_buffer;

  /* create "int" spam score */
  j = (int)((spamd_score + 0.001)*10);
  snprintf(CS spam_score_int_buffer, sizeof(spam_score_int_buffer), "%d", j);
  spam_score_int = spam_score_int_buffer;

  /* compare threshold against score */
  if (spamd_score >= spamd_threshold) {
    /* spam as determined by user's threshold */
    spam_rc = OK;
  }
  else {
    /* not spam */
    spam_rc = FAIL;
  };
  
  /* remember user name and "been here" for it */
  Ustrcpy(prev_user_name, user_name);
  spam_ok = 1;
  
  if (override) {
    /* always return OK, no matter what the score */
    return OK;
  }
  else {
    return spam_rc;
  };
}

#endif
