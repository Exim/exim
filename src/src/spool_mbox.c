/* $Cambridge: exim/src/src/spool_mbox.c,v 1.1.2.1 2004/11/26 09:13:34 tom Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* This file is part of the exiscan-acl content scanner
patch. It is NOT part of the standard exim distribution. */

/* Copyright (c) Tom Kistner <tom@duncanthrax.net> 2003-???? */
/* License: GPL */

/* Code for setting up a MBOX style spool file inside a /scan/<msgid>
sub directory of exim's spool directory. */

#include "exim.h"

/* externals, we must reset them on unspooling */
extern int demime_ok;
extern int malware_ok;
extern int spam_ok;
extern struct file_extension *file_extensions;

int spool_mbox_ok = 0;
uschar spooled_message_id[17];

/* returns a pointer to the FILE, and puts the size in bytes into mbox_file_size */

FILE *spool_mbox(unsigned long long *mbox_file_size) {
  uschar mbox_path[1024];
  uschar message_subdir[2];
  uschar data_buffer[65535];
  FILE *mbox_file;
  FILE *data_file = NULL;
  header_line *my_headerlist;
  struct stat statbuf;
  int i,j;
  
  /*
  uschar *received;
  uschar *timestamp;
  */
  
  if (!spool_mbox_ok) {
    /* create scan directory, if not present */
    if (!directory_make(spool_directory, US "scan", 0750, FALSE)) {
      debug_printf("unable to create directory: %s/scan\n", spool_directory);
      return NULL;
    };
    
    /* create temp directory inside scan dir */
    snprintf(CS mbox_path, 1024, "%s/scan/%s", spool_directory, message_id);
    if (!directory_make(NULL, mbox_path, 0750, FALSE)) {
      debug_printf("unable to create directory: %s/scan/%s\n", spool_directory, message_id);
      return NULL;
    };
    
    /* open [message_id].eml file for writing */
    snprintf(CS mbox_path, 1024, "%s/scan/%s/%s.eml", spool_directory, message_id, message_id);
    mbox_file = Ufopen(mbox_path,"w");
    
    if (mbox_file == NULL) {
      debug_printf("unable to open file for writing: %s\n", mbox_path);
      return NULL;
    };
    
    /* Generate a preliminary Received: header and put it in the file.
       We need to do this so SA can do DNS list checks */
       
    /* removed for 4.34
    
    timestamp = expand_string(US"${tod_full}");
    received = expand_string(received_header_text);
    if (received != NULL) {
      uschar *my_received;
      if (received[0] == 0) {
        my_received = string_sprintf("Received: ; %s\n", timestamp);
      }
      else {
        my_received = string_sprintf("%s; %s\n", received, timestamp);
      }
      i = fwrite(my_received, 1, Ustrlen(my_received), mbox_file);
      if (i != Ustrlen(my_received)) {
        debug_printf("error/short write on writing in: %s", mbox_path);
        fclose(mbox_file);
        return NULL;
      };
    };
    
    */
    
    /* write all header lines to mbox file */
    my_headerlist = header_list;
    while (my_headerlist != NULL) {
      
      /* skip deleted headers */
      if (my_headerlist->type == '*') {
        my_headerlist = my_headerlist->next;
        continue;
      };
  
      i = fwrite(my_headerlist->text, 1, my_headerlist->slen, mbox_file);
      if (i != my_headerlist->slen) {
        debug_printf("error/short write on writing in: %s", mbox_path);
        fclose(mbox_file);
        return NULL;
      };
      
      my_headerlist = my_headerlist->next;
    };
  
    /* copy body file */
    message_subdir[1] = '\0';
    for (i = 0; i < 2; i++) {
      message_subdir[0] = (split_spool_directory == (i == 0))? message_id[5] : 0;
      sprintf(CS mbox_path, "%s/input/%s/%s-D", spool_directory, message_subdir, message_id);
      data_file = Ufopen(mbox_path,"r");
      if (data_file != NULL)
        break;
    };

    fread(data_buffer, 1, 18, data_file);
    
    do {
      j = fread(data_buffer, 1, sizeof(data_buffer), data_file);
      if (j > 0) {
        i = fwrite(data_buffer, 1, j, mbox_file);
        if (i != j) {
          debug_printf("error/short write on writing in: %s", mbox_path);
          fclose(mbox_file);
          fclose(data_file);
          return NULL;
        };
      };
    } while (j > 0);
    
    fclose(data_file);
    fclose(mbox_file);
    Ustrcpy(spooled_message_id, message_id);
    spool_mbox_ok = 1;
  };

  snprintf(CS mbox_path, 1024, "%s/scan/%s/%s.eml", spool_directory, message_id, message_id);

  /* get the size of the mbox message */
  stat(CS mbox_path, &statbuf);
  *mbox_file_size = statbuf.st_size;

  /* open [message_id].eml file for reading */
  mbox_file = Ufopen(mbox_path,"r");
  
  return mbox_file;
}

/* remove mbox spool file, demimed files and temp directory */
void unspool_mbox(void) {

  /* reset all exiscan state variables */
  demime_ok = 0;
  demime_errorlevel = 0;
  demime_reason = NULL;
  file_extensions = NULL;
  spam_ok = 0;
  malware_ok = 0;
  
  if (spool_mbox_ok) {

    spool_mbox_ok = 0;
    
    if (!no_mbox_unspool) {
      uschar mbox_path[1024];
      uschar file_path[1024];
      int n;
      struct dirent *entry;
      DIR *tempdir;
      
      snprintf(CS mbox_path, 1024, "%s/scan/%s", spool_directory, spooled_message_id);
    	
    	tempdir = opendir(CS mbox_path);
    	/* loop thru dir & delete entries */
    	n = 0;
    	do {
    	  entry = readdir(tempdir);
    	  if (entry == NULL) break;
    	  snprintf(CS file_path, 1024,"%s/scan/%s/%s", spool_directory, spooled_message_id, entry->d_name);
    	  if ( (Ustrcmp(entry->d_name,"..") != 0) && (Ustrcmp(entry->d_name,".") != 0) ) {
    	    debug_printf("unspool_mbox(): unlinking '%s'\n", file_path);
              n = unlink(CS file_path);
            }; 
    	} while (n > -1);
    	
    	closedir(tempdir);
    	
    	/* remove directory */
    	n = rmdir(CS mbox_path);
    };
  };
}
