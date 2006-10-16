/* $Cambridge: exim/src/src/auths/dovecot.c,v 1.2 2006/10/16 13:43:22 ph10 Exp $ */

/*
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

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

static int strcut(char *str, char **ptrs, int nptrs)
{
       char *tmp = str;
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
       if (strcasecmp((str), args[0]) != 0) \
               goto out; \
       if (nargs - 1 < (arg_min)) \
               goto out; \
       if (nargs - 1 > (arg_max)) \
               goto out; \
} while (0)

#define OUT(msg) do { \
       auth_defer_msg = (US msg); \
       goto out; \
} while(0)



/*************************************************
 *             Server entry point                *
 *************************************************/

int auth_dovecot_server(auth_instance *ablock, uschar *data)
{
       auth_dovecot_options_block *ob =
               (auth_dovecot_options_block *)(ablock->options_block);
       struct sockaddr_un sa;
       char buffer[4096];
       char *args[8];
       uschar *auth_command;
       uschar *auth_extra_data = US"";
       int nargs, tmp;
       int cuid = 0, cont = 1, found = 0, fd, ret = DEFER;
       FILE *f;

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

       f = fdopen(fd, "a+");
       if (f == NULL)
               goto out;

       auth_defer_msg = US"authentication socket protocol error";

       while (cont) {
               if (fgets(buffer, sizeof(buffer), f) == NULL)
                       OUT("authentication socket read error or premature eof");

               buffer[strlen(buffer) - 1] = 0;
               HDEBUG(D_auth) debug_printf("received: %s\n", buffer);
               nargs = strcut(buffer, args, sizeof(args) / sizeof(args[0]));

               switch (toupper(*args[0])) {
               case 'C':
                       CHECK_COMMAND("CUID", 1, 1);
                       cuid = atoi(args[1]);
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
                       if (atoi(args[1]) != VERSION_MAJOR)
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
       else if (Ustrcmp(sender_host_address, interface_address) == 0)
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
****************************************************************************/

       auth_command = string_sprintf("VERSION\t%d\t%d\nCPID\t%d\n"
               "AUTH\t%d\t%s\tservice=smtp\t%srip=%s\tlip=%s\tresp=%s\n",
               VERSION_MAJOR, VERSION_MINOR, getpid(), cuid,
               ablock->public_name, auth_extra_data, sender_host_address,
               interface_address, data ? (char *) data : "");

       fprintf(f, "%s", auth_command);
       HDEBUG(D_auth) debug_printf("sent: %s", auth_command);

       while (1) {
               if (fgets(buffer, sizeof(buffer), f) == NULL) {
                       auth_defer_msg = US"authentication socket read error or premature eof";
                       goto out;
               }

               buffer[strlen(buffer) - 1] = 0;
               HDEBUG(D_auth) debug_printf("received: %s\n", buffer);
               nargs = strcut(buffer, args, sizeof(args) / sizeof(args[0]));

               if (atoi(args[1]) != cuid)
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

                       if (fprintf(f, "CONT\t%d\t%s\r\n", cuid, data) < 0)
                               OUT("authentication socket write error");

                       break;

               case 'F':
                       CHECK_COMMAND("FAIL", 1, 2);

                       /* FIXME: add proper response handling */
                       if (args[2]) {
                               uschar *p = US strchr(args[2], '=');
                               if (p) {
                                       ++p;
                                       expand_nstring[1] = auth_vars[0] = p;
                                       expand_nlength[1] = Ustrlen(p);
                                       expand_nmax = 1;
                               }
                       }

                       ret = FAIL;
                       goto out;

               case 'O':
                       CHECK_COMMAND("OK", 2, 2);
                       {
                               /* FIXME: add proper response handling */
                               uschar *p = US strchr(args[2], '=');
                               if (!p)
                                       OUT("authentication socket protocol error, username missing");

                               p++;
                               expand_nstring[1] = auth_vars[0] = p;
                               expand_nlength[1] = Ustrlen(p);
                               expand_nmax = 1;
                       }
                       ret = OK;
                       /* fallthrough */

               default:
                       goto out;
               }
       }

out:   close(fd);
       return ret;
}
