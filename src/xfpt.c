/*************************************************
*     xfpt - Simple ASCII->Docbook processor     *
*************************************************/

/* Copyright (c) University of Cambridge, 2007 */
/* Written by Philip Hazel. */

/* This module contains the main program and initialization functions. */

#include "xfpt.h"



/*************************************************
*                 Static variables               *
*************************************************/

static uschar *xfpt_filename = NULL;
static uschar *out_filename = NULL;


/*************************************************
*                  Usage                         *
*************************************************/

static void
usage(void)
{
(void)fprintf(stderr,
  "Usage: xfpt [-help]\n"
  "            [-o <output-file>]\n"
  "            [-S <share-directory>]\n"
  "            [-v]\n"
  "            [input-file]\n");
}




/*************************************************
*          Command line argument decoding        *
*************************************************/

/* Arguments: as for main()
   Returns:   TRUE if OK
*/

static BOOL
xfpt_decode_arg(int argc, char **argv)
{
int i;
for (i = 1; i < argc; i++)
  {
  uschar *arg = US argv[i];
  if (*arg != '-') break;
  if (Ustrcmp(arg, "-o") == 0)
    {
    out_filename = US argv[++i];
    if (out_filename == NULL) { usage(); return FALSE; }
    }
  else if (Ustrcmp(arg, "-S") == 0)
    {
    xfpt_share = US argv[++i];
    if (xfpt_share == NULL) { usage(); return FALSE; }
    }
  else if (Ustrcmp(arg, "-help") == 0 || Ustrcmp(arg, "--help") == 0)
    {
    usage();
    return FALSE;
    }
  else if (Ustrcmp(arg, "-v") == 0)
    {
    (void)fprintf(stdout, "xpft version %s\n", xfpt_version);
    exit(0);
    }
  else
    {
    (void)fprintf(stderr, "xfpt: unknown option \"%s\"\n", arg);
    usage();
    return FALSE;
    }
  }

/* Require there to be either 0 or 1 command line argument left. */

if (argc > i + 1)
  {
  usage();
  return FALSE;
  }

/* This will set NULL if there is no file name. If there is a file name and no
output file is specified, default it to the input name with a .xml extension. */

xfpt_filename = US argv[i];
if (xfpt_filename != NULL && out_filename == NULL)
  {
  uschar *p;
  int len = Ustrlen(xfpt_filename);
  out_filename = misc_malloc(len + 5);
  Ustrcpy(out_filename, xfpt_filename);
  if ((p = Ustrrchr(out_filename, '.')) != NULL) len = p - out_filename;
  Ustrcpy(out_filename + len, ".xml");
  }

return TRUE;
}



/*************************************************
*          Entry point and main program          *
*************************************************/


int
main(int argc, char **argv)
{
uschar *p, *q;

if (!xfpt_decode_arg(argc, argv)) return EXIT_FAILURE;

inbuffer = misc_malloc(INBUFFSIZE);
parabuffer = misc_malloc(PARABUFFSIZE);

/* Set up the first file */

istack = misc_malloc(sizeof(istackstr));
istack->prev = NULL;
istack->linenumber = 0;

if (xfpt_filename == NULL)
  {
  istack->file = stdin;
  Ustrcpy(istack->filename, US"(stdin)");
  }
else
  {
  Ustrcpy(istack->filename, xfpt_filename);
  istack->file = Ufopen(xfpt_filename, "rb");
  if (istack->file == NULL)
    error(0, istack->filename, strerror(errno));    /* Hard */
  }

/* Set up the output file. */

if (out_filename == NULL || Ustrcmp(out_filename, "-") == 0)
  {
  outfile = stdout;
  }
else
  {
  outfile = Ufopen(out_filename, "wb");
  if (outfile == NULL)
    error(0, out_filename, strerror(errno));   /* Hard error */
  }

/* Process the input */

while ((p = read_nextline()) != NULL)
  {
  if (*p == '.') dot_process(p); else switch (literal_state)
    {
    case LITERAL_LAYOUT:
    para_process(p);
    break;

    case LITERAL_TEXT:
    literal_process(p);
    break;

    case LITERAL_XML:
    (void)fprintf(outfile, "%s", CS p);
    break;

    default:
    case LITERAL_OFF:
    q = p;
    while (isspace(*q)) q++;
    if (*q != 0)
      {
      p = read_paragraph(p);
      (void)fprintf(outfile, "<");
      para_process(US"para&xfpt.rev;");
      (void)fprintf(outfile, ">\n");
      para_process(p);
      (void)fprintf(outfile, "</para>\n");
      }
    break;
    }
  }

/* Empty the pushed stack, close the output, and we are done */

while (pushed != 0)
  {
  para_process(pushed->string);
  (void)fprintf(outfile, "\n");
  pushed = pushed->next;
  }

(void)fclose(outfile);

return return_code;
}

/* End of xfpt.c */
