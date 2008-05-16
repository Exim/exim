/* $Cambridge: exim/src/src/auths/dovecot.c,v 1.10 2008/05/16 12:22:08 nm4 Exp $ */

/*
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* A number of modifications have been made to the original code. Originally I
commented them specially, but now they are getting quite extensive, so I have
ceased doing that. The biggest change is to use unbuffered I/O on the socket
because using C buffered I/O gives problems on some operating systems. PH */

#include "../exim.h"
#include "dovecot.h"

#define VERSION_MAJOR  1
#define VERSION_MINOR  0

/* Options specific to the authentication mechanism. */
optionlist auth_dovecot_options[] = {
       {
       "server_socket",
       opt_stringptr,
       (void *)(offsetof(auth_dovecot_options_block, server_socket))
       },
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int auth_dovecot_options_count =
       sizeof(auth_dovecot_options) / sizeof(optionlist);

/* Default private options block for the authentication method. */

auth_dovecot_options_block auth_dovecot_option_defaults = {
       NULL,                           /* server_socket */
};


/* Static variables for reading from the socket */

static uschar sbuffer[256];
static int sbp;



/*************************************************
 *          Initialization entry point           *
 *************************************************/

/* Called for each instance, after its options have been read, to
enable consistency checks to be done, or anything else that needs
to be set up. */

void auth_dovecot_init(auth_instance *ablock)
{
       auth_dovecot_options_block *ob =
               (auth_dovecot_options_block *)(ablock->options_block);

       if (ablock->public_name == NULL)
               ablock->public_name = ablock->name;
       if (ob->server_socket != NULL)
               ablock->server = TRUE;
       ablock->client = FALSE;
}

static int strcut(uschar *str, uschar **ptrs, int nptrs)
{
       uschar *tmp = str;
       int n;

       for (n = 0; n < nptrs; n++)
               ptrs[n] = NULL;
       n = 1;

       while (*str) {
               if (*str == '\t') {
                       if (n <= nptrs) {
                               *ptrs++ = tmp;
                               tmp = str + 1;
                               *str = 0;
                       }
                       n++;
               }
               str++;
       }

       if (n < nptrs)
               *ptrs = tmp;

       return n;
}

#define CHECK_COMMAND(str, arg_min, arg_max) do { \
       if (strcmpic(US(str), args[0]) != 0) \
               goto out; \
       if (nargs - 1 < (arg_min)) \
               goto out; \
       if ( (arg_max != -1) && (nargs - 1 > (arg_max)) ) \
               goto out; \
} while (0)

#define OUT(msg) do { \
       auth_defer_msg = (US msg); \
       goto out; \
} while(0)



/*************************************************
*      "fgets" to read directly from socket      *
*************************************************/

/* Added by PH after a suggestion by Steve Usher because the previous use of
C-style buffered I/O gave trouble. */

static uschar *
dc_gets(uschar *s, int n, int fd)
{
int p = 0;
int count = 0;

for (;;)
  {
  if (sbp == 0)
    {
    sbp = read(fd, sbuffer, sizeof(sbuffer));
    if (sbp == 0) { if (count == 0) return NULL; else break; }
    }

  while (p < sbp)
    {
    if (count >= n - 1) break;
    s[count++] = sbuffer[p];
    if (sbuffer[p++] == '\n') break;
    }

  memmove(sbuffer, sbuffer + p, sbp - p);
  sbp -= p;

  if (s[count-1] == '\n' || count >= n - 1) break;
  }

s[count] = 0;
return s;
}




/*************************************************
*              Server entry point                *
*************************************************/

int auth_dovecot_server(auth_instance *ablock, uschar *data)
{
       auth_dovecot_options_block *ob =
               (auth_dovecot_options_block *)(ablock->options_block);
       struct sockaddr_un sa;
       uschar buffer[4096];
       uschar *args[8];
       uschar *auth_command;
       uschar *auth_extra_data = US"";
       int nargs, tmp;
       int cuid = 0, cont = 1, found = 0, fd, ret = DEFER;

       HDEBUG(D_auth) debug_printf("dovecot authentication\n");

       memset(&sa, 0, sizeof(sa));
       sa.sun_family = AF_UNIX;

       /* This was the original code here: it is nonsense because strncpy()
       does not return an integer. I have converted this to use the function
       that formats and checks length. PH */

       /*
       if (strncpy(sa.sun_path, ob->server_socket, sizeof(sa.sun_path)) < 0) {
       */

       if (!string_format(US sa.sun_path, sizeof(sa.sun_path), "%s",
                          ob->server_socket)) {
               auth_defer_msg = US"authentication socket path too long";
               return DEFER;
       }

       auth_defer_msg = US"authentication socket connection error";

       fd = socket(PF_UNIX, SOCK_STREAM, 0);
       if (fd < 0)
               return DEFER;

       if (connect(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
               goto out;

       auth_defer_msg = US"authentication socket protocol error";

       sbp = 0;  /* Socket buffer pointer */
       while (cont) {
               if (dc_gets(buffer, sizeof(buffer), fd) == NULL)
                       OUT("authentication socket read error or premature eof");

               buffer[Ustrlen(buffer) - 1] = 0;
               HDEBUG(D_auth) debug_printf("received: %s\n", buffer);
               nargs = strcut(buffer, args, sizeof(args) / sizeof(args[0]));

               switch (toupper(*args[0])) {
               case 'C':
                       CHECK_COMMAND("CUID", 1, 1);
                       cuid = Uatoi(args[1]);
                       break;

               case 'D':
                       CHECK_COMMAND("DONE", 0, 0);
                       cont = 0;
                       break;

               case 'M':
                       CHECK_COMMAND("MECH", 1, INT_MAX);
                       if (strcmpic(US args[1], ablock->public_name) == 0)
                               found = 1;
                       break;

               case 'S':
                       CHECK_COMMAND("SPID", 1, 1);
                       break;

               case 'V':
                       CHECK_COMMAND("VERSION", 2, 2);
                       if (Uatoi(args[1]) != VERSION_MAJOR)
                               OUT("authentication socket protocol version mismatch");
                       break;

               default:
                       goto out;
               }
       }

       if (!found)
               goto out;

       /* Added by PH: data must not contain tab (as it is
       b64 it shouldn't, but check for safety). */

       if (Ustrchr(data, '\t') != NULL) {
               ret = FAIL;
               goto out;
       }

       /* Added by PH: extra fields when TLS is in use or if the TCP/IP
       connection is local. */

       if (tls_cipher != NULL)
               auth_extra_data = string_sprintf("secured\t%s%s",
                   tls_certificate_verified? "valid-client-cert" : "",
                   tls_certificate_verified? "\t" : "");
       else if (interface_address != NULL &&
                Ustrcmp(sender_host_address, interface_address) == 0)
               auth_extra_data = US"secured\t";


/****************************************************************************
   The code below was the original code here. It didn't work. A reading of the
   file auth-protocol.txt.gz that came with Dovecot 1.0_beta8 indicated that
   this was not right. Maybe something changed. I changed it to move the
   service indication into the AUTH command, and it seems to be better. PH

       fprintf(f, "VERSION\t%d\t%d\r\nSERVICE\tSMTP\r\nCPID\t%d\r\n"
               "AUTH\t%d\t%s\trip=%s\tlip=%s\tresp=%s\r\n",
               VERSION_MAJOR, VERSION_MINOR, getpid(), cuid,
               ablock->public_name, sender_host_address, interface_address,
               data ? (char *) data : "");

   Subsequently, the command was modified to add "secured" and "valid-client-
   cert" when relevant.

   The auth protocol is documented here:
        http://wiki.dovecot.org/Authentication_Protocol
****************************************************************************/

       auth_command = string_sprintf("VERSION\t%d\t%d\nCPID\t%d\n"
               "AUTH\t%d\t%s\tservice=smtp\t%srip=%s\tlip=%s\tnologin\tresp=%s\n",
               VERSION_MAJOR, VERSION_MINOR, getpid(), cuid,
               ablock->public_name, auth_extra_data, sender_host_address,
               interface_address, data ? (char *) data : "");

       if (write(fd, auth_command, Ustrlen(auth_command)) < 0)
              HDEBUG(D_auth) debug_printf("error sending auth_command: %s\n",
                strerror(errno));

       HDEBUG(D_auth) debug_printf("sent: %s", auth_command);

       while (1) {
               uschar *temp;
               uschar *auth_id_pre = NULL;
               int i;

               if (dc_gets(buffer, sizeof(buffer), fd) == NULL) {
                       auth_defer_msg = US"authentication socket read error or premature eof";
                       goto out;
               }

               buffer[Ustrlen(buffer) - 1] = 0;
               HDEBUG(D_auth) debug_printf("received: %s\n", buffer);
               nargs = strcut(buffer, args, sizeof(args) / sizeof(args[0]));

               if (Uatoi(args[1]) != cuid)
                       OUT("authentication socket connection id mismatch");

               switch (toupper(*args[0])) {
               case 'C':
                       CHECK_COMMAND("CONT", 1, 2);

                       tmp = auth_get_no64_data(&data, US args[2]);
                       if (tmp != OK) {
                               ret = tmp;
                               goto out;
                       }

                       /* Added by PH: data must not contain tab (as it is
                       b64 it shouldn't, but check for safety). */

                       if (Ustrchr(data, '\t') != NULL) {
                               ret = FAIL;
                               goto out;
                       }

                       temp = string_sprintf("CONT\t%d\t%s\n", cuid, data);
                       if (write(fd, temp, Ustrlen(temp)) < 0)
                               OUT("authentication socket write error");
                       break;

               case 'F':
                       CHECK_COMMAND("FAIL", 1, -1);

                       for (i=2; (i<nargs) && (auth_id_pre == NULL); i++)
                       {
                               if ( Ustrncmp(args[i], US"user=", 5) == 0 )
                               {
                                       auth_id_pre = args[i]+5;
                                       expand_nstring[1] = auth_vars[0] =
                                               string_copy(auth_id_pre); /* PH */
                                       expand_nlength[1] = Ustrlen(auth_id_pre);
                                       expand_nmax = 1;
                               }
                       }

                       ret = FAIL;
                       goto out;

               case 'O':
                       CHECK_COMMAND("OK", 2, -1);

                       /*
                        * Search for the "user=$USER" string in the args array
                        * and return the proper value.
                        */
                       for (i=2; (i<nargs) && (auth_id_pre == NULL); i++)
                       {
                               if ( Ustrncmp(args[i], US"user=", 5) == 0 )
                               {
                                       auth_id_pre = args[i]+5;
                                       expand_nstring[1] = auth_vars[0] =
                                               string_copy(auth_id_pre); /* PH */
                                       expand_nlength[1] = Ustrlen(auth_id_pre);
                                       expand_nmax = 1;
                               }
                       }

                       if (auth_id_pre == NULL)
                               OUT("authentication socket protocol error, username missing");

                       ret = OK;
                       /* fallthrough */

               default:
                       goto out;
               }
       }

out:
       /* close the socket used by dovecot */
       if (fd >= 0)
              close(fd);

       /* Expand server_condition as an authorization check */
       return (ret == OK)? auth_check_serv_cond(ablock) : ret;
}
