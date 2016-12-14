/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Tom Kistner <tom@duncanthrax.net> 2003 - 2015
 * License: GPL
 * Copyright (c) The Exim Maintainers 2016
 */

/* Code for setting up a MBOX style spool file inside a /scan/<msgid>
sub directory of exim's spool directory. */

#include "exim.h"
#ifdef WITH_CONTENT_SCAN

extern int malware_ok;
extern int spam_ok;

int spool_mbox_ok = 0;
uschar spooled_message_id[MESSAGE_ID_LENGTH+1];

/* returns a pointer to the FILE, and puts the size in bytes into mbox_file_size
 * normally, source_file_override is NULL */

FILE *
spool_mbox(unsigned long *mbox_file_size, const uschar *source_file_override)
{
uschar message_subdir[2];
uschar buffer[16384];
uschar *temp_string;
uschar *mbox_path;
FILE *mbox_file = NULL;
FILE *data_file = NULL;
FILE *yield = NULL;
header_line *my_headerlist;
struct stat statbuf;
int i, j;
void *reset_point = store_get(0);

mbox_path = string_sprintf("%s/scan/%s/%s.eml", spool_directory, message_id,
  message_id);

/* Skip creation if already spooled out as mbox file */
if (!spool_mbox_ok)
  {
  /* create temp directory inside scan dir, directory_make works recursively */
  temp_string = string_sprintf("scan/%s", message_id);
  if (!directory_make(spool_directory, temp_string, 0750, FALSE))
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "%s", string_open_failed(errno,
      "scan directory %s/scan/%s", spool_directory, temp_string));
    goto OUT;
    }

  /* open [message_id].eml file for writing */
  mbox_file = modefopen(mbox_path, "wb", SPOOL_MODE);
  if (mbox_file == NULL)
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "%s", string_open_failed(errno,
      "scan file %s", mbox_path));
    goto OUT;
    }

  /* Generate mailbox headers. The $received_for variable is (up to at least
  Exim 4.64) never set here, because it is only set when expanding the
  contents of the Received: header line. However, the code below will use it
  if it should become available in future. */

  temp_string = expand_string(
    US"From ${if def:return_path{$return_path}{MAILER-DAEMON}} ${tod_bsdinbox}\n"
    "${if def:sender_address{X-Envelope-From: <${sender_address}>\n}}"
    "${if def:recipients{X-Envelope-To: ${recipients}\n}}");

  if (temp_string != NULL)
    {
    i = fwrite(temp_string, Ustrlen(temp_string), 1, mbox_file);
    if (i != 1)
      {
      log_write(0, LOG_MAIN|LOG_PANIC, "Error/short write while writing \
	  mailbox headers to %s", mbox_path);
      goto OUT;
      }
    }

  /* write all header lines to mbox file */
  my_headerlist = header_list;
  for (my_headerlist = header_list; my_headerlist != NULL;
    my_headerlist = my_headerlist->next)
    {
    /* skip deleted headers */
    if (my_headerlist->type == '*') continue;

    i = fwrite(my_headerlist->text, my_headerlist->slen, 1, mbox_file);
    if (i != 1)
      {
      log_write(0, LOG_MAIN|LOG_PANIC, "Error/short write while writing \
	  message headers to %s", mbox_path);
      goto OUT;
      }
    }

  /* End headers */
  if (fwrite("\n", 1, 1, mbox_file) != 1)
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "Error/short write while writing \
      message headers to %s", mbox_path);
    goto OUT;
    }

  /* copy body file */
  if (source_file_override == NULL)
    {
    message_subdir[1] = '\0';
    for (i = 0; i < 2; i++)
      {
      message_subdir[0] = split_spool_directory == (i == 0) ? message_id[5] : 0;
      temp_string = spool_fname(US"input", message_subdir, message_id, US"-D");
      if ((data_file = Ufopen(temp_string, "rb"))) break;
      }
    }
  else
    data_file = Ufopen(source_file_override, "rb");

  if (!data_file)
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "Could not open datafile for message %s",
      message_id);
    goto OUT;
    }

  /* The code used to use this line, but it doesn't work in Cygwin.

      (void)fread(data_buffer, 1, 18, data_file);
    
     What's happening is that spool_mbox used to use an fread to jump over the
     file header. That fails under Cygwin because the header is locked, but
     doing an fseek succeeds. We have to output the leading newline
     explicitly, because the one in the file is parted of the locked area.  */

  if (!source_file_override)
    (void)fseek(data_file, SPOOL_DATA_START_OFFSET, SEEK_SET);

  do
    {
    j = fread(buffer, 1, sizeof(buffer), data_file);

    if (j > 0)
      {
      i = fwrite(buffer, j, 1, mbox_file);
      if (i != 1)
        {
	log_write(0, LOG_MAIN|LOG_PANIC, "Error/short write while writing \
	    message body to %s", mbox_path);
	goto OUT;
	}
      }
    } while (j > 0);

  (void)fclose(mbox_file);
  mbox_file = NULL;

  Ustrncpy(spooled_message_id, message_id, sizeof(spooled_message_id));
  spooled_message_id[sizeof(spooled_message_id)-1] = '\0';
  spool_mbox_ok = 1;
  }

/* get the size of the mbox message and open [message_id].eml file for reading*/

if (  !(yield = Ufopen(mbox_path,"rb"))
   || fstat(fileno(yield), &statbuf) != 0
   )
  log_write(0, LOG_MAIN|LOG_PANIC, "%s", string_open_failed(errno,
    "scan file %s", mbox_path));
else
  *mbox_file_size = statbuf.st_size;

OUT:
if (data_file) (void)fclose(data_file);
if (mbox_file) (void)fclose(mbox_file);
store_reset(reset_point);
return yield;
}





/* remove mbox spool file and temp directory */
void
unspool_mbox(void)
{
spam_ok = 0;
malware_ok = 0;

if (spool_mbox_ok && !no_mbox_unspool)
  {
  uschar *mbox_path;
  uschar *file_path;
  struct dirent *entry;
  DIR *tempdir;

  mbox_path = string_sprintf("%s/scan/%s", spool_directory, spooled_message_id);

  tempdir = opendir(CS mbox_path);
  if (!tempdir)
    {
    debug_printf("Unable to opendir(%s): %s\n", mbox_path, strerror(errno));
    /* Just in case we still can: */
    rmdir(CS mbox_path);
    return;
    }
  /* loop thru dir & delete entries */
  while((entry = readdir(tempdir)) != NULL)
    {
    uschar *name = US entry->d_name;
    int dummy;
    if (Ustrcmp(name, US".") == 0 || Ustrcmp(name, US"..") == 0) continue;

    file_path = string_sprintf("%s/%s", mbox_path, name);
    debug_printf("unspool_mbox(): unlinking '%s'\n", file_path);
    dummy = unlink(CS file_path);
    }

  closedir(tempdir);

  /* remove directory */
  rmdir(CS mbox_path);
  store_reset(mbox_path);
  }
spool_mbox_ok = 0;
}

#endif
