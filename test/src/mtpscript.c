/* $Cambridge: exim/test/src/mtpscript.c,v 1.1 2006/02/06 16:24:05 ph10 Exp $ */

/* A little hacked up program that allows a script to play the part of a remote
SMTP/LMTP server on stdin/stdout for testing purposes. Hacked from the more
complicated version that does it over a socket. */


/* ANSI C standard includes */

#include <ctype.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Unix includes */

#include <errno.h>
#include <unistd.h>


static FILE *log;


/*************************************************
*            SIGALRM handler - crash out         *
*************************************************/

static void
sigalrm_handler(int sig)
{
sig = sig;    /* Keep picky compilers happy */
fprintf(log, "Server timed out\n");
exit(99);
}



/*************************************************
*                 Main Program                   *
*************************************************/

int main(int argc, char **argv)
{
char *logfile;
char *logmode = "w";
FILE *script;
unsigned char sbuffer[1024];
unsigned char ibuffer[1024];

if (argc < 3)
  {
  fprintf(stdout, "500 Script and log file required\n");
  exit(1);
  }

/* Get the script and log open */

script = fopen(argv[1], "r");
if (script == NULL)
  {
  fprintf(stdout, "500 Failed to open script %s: %s\r\n", argv[1],
    strerror(errno));
  exit(1);
  }

logfile = argv[2];
if (logfile[0] == '+')
  {
  logfile++;
  logmode = "a";
  }

log = fopen(logfile, logmode);
if (log == NULL)
  {
  fprintf(stdout, "500 Failed to open log %s: %s\r\n", logfile,
    strerror(errno));
  exit(1);
  }

/* SIGALRM handler crashes out */

signal(SIGALRM, sigalrm_handler);

/* Read the script, and do what it says. */

while (fgets(sbuffer, sizeof(sbuffer), script) != NULL)
  {
  int n = (int)strlen(sbuffer);
  while (n > 0 && isspace(sbuffer[n-1])) n--;
  sbuffer[n] = 0;

  /* If the script line starts with a digit, it is a response line which
  we are to send. */

  if (isdigit(sbuffer[0]))
    {
    fprintf(log, "%s\n", sbuffer);
    fflush(log);
    fprintf(stdout, "%s\r\n", sbuffer);
    fflush(stdout);
    }

  /* If the script line starts with "*sleep" we just sleep for a while
  before continuing. Do not write this to the log, as it may not get
  written at the right place in a log that's being shared. */

  else if (strncmp(sbuffer, "*sleep ", 7) == 0)
    {
    sleep(atoi(sbuffer+7));
    }

  /* Otherwise the script line is the start of an input line we are expecting
  from the client, or "*eof" indicating we expect the client to close the
  connection. Read command line or data lines; the latter are indicated
  by the expected line being just ".". */

  else
    {
    int data = strcmp(sbuffer, ".") == 0;

    fprintf(log, "%s\n", sbuffer);
    fflush(log);

    /* Loop for multiple data lines */

    for (;;)
      {
      int n;
      alarm(5);
      if (fgets(ibuffer, sizeof(ibuffer), stdin) == NULL)
        {
        fprintf(log, "%sxpected EOF read from client\n",
          (strncmp(sbuffer, "*eof", 4) == 0)? "E" : "Une");
        goto END_OFF;
        }
      alarm(0);
      n = (int)strlen(ibuffer);
      while (n > 0 && isspace(ibuffer[n-1])) n--;
      ibuffer[n] = 0;
      fprintf(log, "<<< %s\n", ibuffer);
      if (!data || strcmp(ibuffer, ".") == 0) break;
      }

    /* Check received what was expected */

    if (strncmp(sbuffer, ibuffer, (int)strlen(sbuffer)) != 0)
      {
      fprintf(log, "Comparison failed - bailing out\n");
      goto END_OFF;
      }
    }
  }

/* This could appear in the wrong place in a shared log, so forgo it. */
/* fprintf(log, "End of script\n"); */

END_OFF:
fclose(script);
fclose(log);

exit(0);
}

/* End of mtpscript.c */
