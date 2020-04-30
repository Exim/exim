/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* Copyright (c) The Exim Maintainers 2020 */
/* See the file NOTICE for conditions of use and distribution. */

/* A function for returning the time of day in various formats */


#include "exim.h"

/* #define TESTING_LOG_DATESTAMP */


static uschar timebuf[sizeof("www, dd-mmm-yyyy hh:mm:ss.ddd +zzzz")];


/*************************************************
*                Return timestamp                *
*************************************************/

/* The log timestamp format is dd-mmm-yy so as to be non-confusing on both
sides of the Atlantic. We calculate an explicit numerical offset from GMT for
the full datestamp and BSD inbox datestamp. Note that on some systems
localtime() and gmtime() re-use the same store, so we must save the local time
values before calling gmtime(). If timestamps_utc is set, don't use
localtime(); all times are then in UTC (with offset +0000).

There are also some contortions to get the day of the month without
a leading zero for the full stamp, since Ustrftime() doesn't provide this
option.

Argument:  type of timestamp required:
             tod_bsdin                  BSD inbox format
             tod_epoch                  Unix epoch format
             tod_epochl                 Unix epoch/usec format
             tod_full                   full date and time
             tod_log                    log file data line format,
                                          with zone if log_timezone is TRUE
             tod_log_bare               always without zone
             tod_log_datestamp_daily    for log file names when datestamped daily
             tod_log_datestamp_monthly  for log file names when datestamped monthly
             tod_log_zone               always with zone
             tod_mbx                    MBX inbox format
             tod_zone                   just the timezone offset
             tod_zulu                   time in 8601 zulu format

Returns:   pointer to fixed buffer containing the timestamp
*/

uschar *
tod_stamp(int type)
{
struct timeval now;
struct tm * t;

gettimeofday(&now, NULL);

/* Styles that don't need local time */

switch(type)
  {
  case tod_epoch:
    (void) snprintf(CS timebuf, sizeof(timebuf), TIME_T_FMT, now.tv_sec);  /* Unix epoch format */
    return timebuf;	/* NB the above will be wrong if time_t is FP */

  case tod_epoch_l:
    /* Unix epoch/usec format */
    (void) snprintf(CS timebuf, sizeof(timebuf), TIME_T_FMT "%06ld", now.tv_sec, (long) now.tv_usec );
    return timebuf;

  case tod_zulu:
    t = gmtime(&now.tv_sec);
    (void) snprintf(CS timebuf, sizeof(timebuf), "%04u%02u%02u%02u%02u%02uZ",
      1900 + (uint)t->tm_year, 1 + (uint)t->tm_mon, (uint)t->tm_mday, (uint)t->tm_hour, (uint)t->tm_min,
      (uint)t->tm_sec);
    return timebuf;
  }

/* Vary log type according to timezone requirement */

if (type == tod_log) type = log_timezone ? tod_log_zone : tod_log_bare;

/* Convert to local time or UTC */

t = f.timestamps_utc ? gmtime(&now.tv_sec) : localtime(&now.tv_sec);

switch(type)
  {
  case tod_log_bare:          /* Format used in logging without timezone */
#ifndef COMPILE_UTILITY
    if (LOGGING(millisec))
      snprintf(CS timebuf, sizeof(timebuf), "%04u-%02u-%02u %02u:%02u:%02u.%03u",
	1900 + (uint)t->tm_year, 1 + (uint)t->tm_mon, (uint)t->tm_mday,
	(uint)t->tm_hour, (uint)t->tm_min, (uint)t->tm_sec,
	(uint)(now.tv_usec/1000));
    else
#endif
      snprintf(CS timebuf, sizeof(timebuf), "%04u-%02u-%02u %02u:%02u:%02u",
	1900 + (uint)t->tm_year, 1 + (uint)t->tm_mon, (uint)t->tm_mday,
	(uint)t->tm_hour, (uint)t->tm_min, (uint)t->tm_sec);

    break;

    /* Format used as suffix of log file name when 'log_datestamp' is active. For
    testing purposes, it changes the file every second. */

#ifdef TESTING_LOG_DATESTAMP
  case tod_log_datestamp_daily:
  case tod_log_datestamp_monthly:
    snprintf(CS timebuf, sizeof(timebuf), "%04u%02u%02u%02u%02u",
      1900 + (uint)t->tm_year, 1 + (uint)t->tm_mon, (uint)t->tm_mday,
      (uint)t->tm_hour, (uint)t->tm_min);
    break;

#else
  case tod_log_datestamp_daily:
    snprintf(CS timebuf, sizeof(timebuf), "%04u%02u%02u",
      1900 + (uint)t->tm_year, 1 + (uint)t->tm_mon, (uint)t->tm_mday);
    break;

  case tod_log_datestamp_monthly:
#ifndef COMPILE_UTILITY
    snprintf(CS timebuf, sizeof(timebuf), "%04u%02u",
      1900 + (uint)t->tm_year, 1 + (uint)t->tm_mon);
#endif
    break;
#endif

    /* Format used in BSD inbox separator lines. Sort-of documented in RFC 976
    ("UUCP Mail Interchange Format Standard") but only by example, not by
    explicit definition. The examples show no timezone offsets, and some MUAs
    appear to be sensitive to this, so Exim has been changed to remove the
    timezone offsets that originally appeared. */

  case tod_bsdin:
      {
      int len = Ustrftime(timebuf, sizeof(timebuf), "%a %b %d %H:%M:%S", t);
      Ustrftime(timebuf + len, sizeof(timebuf) - len, " %Y", t);
      }
    break;

    /* Other types require the GMT offset to be calculated, or just set up in the
    case of UTC timestamping. We need to take a copy of the local time first. */

  default:
      {
      int diff_hour, diff_min;
      struct tm local;
      struct tm * lp = &local;
      memcpy(lp, t, sizeof(struct tm));

      if (f.timestamps_utc)
	diff_hour = diff_min = 0;
      else
	{
	struct tm * gmt = gmtime(&now.tv_sec);

	if (local.tm_sec == gmt->tm_sec)	/* usual case */
	  {
	  diff_min = 60 * (local.tm_hour - gmt->tm_hour)
		    + local.tm_min - gmt->tm_min;
	  if (local.tm_year != gmt->tm_year)
	    diff_min += (local.tm_year > gmt->tm_year) ? 1440 : -1440;
	  else if (local.tm_yday != gmt->tm_yday)
	    diff_min += (local.tm_yday > gmt->tm_yday) ? 1440 : -1440;
	  diff_hour = diff_min/60;
	  diff_min  = abs(diff_min - diff_hour*60);
	  }
	else					/* subminute offset, eg. TAI */
	  {
	  lp = gmt;				/* pretend we're in UTC */
	  diff_min = diff_hour = 0;
	  }
	}

      switch(type)
	{
	case tod_log_zone:          /* Format used in logging with timezone */
#ifndef COMPILE_UTILITY
	  if (LOGGING(millisec))
	    (void) snprintf(CS timebuf, sizeof(timebuf),
	      "%04u-%02u-%02u %02u:%02u:%02u.%03u %+03d%02d",
	      1900 + (uint)lp->tm_year, 1 + (uint)lp->tm_mon, (uint)lp->tm_mday,
	      (uint)lp->tm_hour, (uint)lp->tm_min, (uint)lp->tm_sec, (uint)(now.tv_usec/1000),
	      diff_hour, diff_min);
	  else
#endif
	    (void) snprintf(CS timebuf, sizeof(timebuf),
	      "%04u-%02u-%02u %02u:%02u:%02u %+03d%02d",
	      1900 + (uint)lp->tm_year, 1 + (uint)lp->tm_mon, (uint)lp->tm_mday,
	      (uint)lp->tm_hour, (uint)lp->tm_min, (uint)lp->tm_sec,
	      diff_hour, diff_min);
	  break;

	case tod_zone:              /* Just the timezone offset */
	  (void) snprintf(CS timebuf, sizeof(timebuf), "%+03d%02d", diff_hour, diff_min);
	  break;

	/* tod_mbx: format used in MBX mailboxes - subtly different to tod_full */

#ifdef SUPPORT_MBX
	case tod_mbx:
	  {
	  int len = snprintf(CS timebuf, sizeof(timebuf),
	    "%02u-", (uint)lp->tm_mday);
	  len += Ustrftime(timebuf + len, sizeof(timebuf) - len,
	    "%b-%Y %H:%M:%S", lp);
	  (void) snprintf(CS timebuf + len, sizeof(timebuf)-len,
	    " %+03d%02d", diff_hour, diff_min);
	  }
	  break;
#endif

	/* tod_full: format used in Received: headers (use as default just in case
	called with a junk type value) */

	default:
	  {
	  int len = Ustrftime(timebuf, sizeof(timebuf), "%a, ", lp);
	  len += snprintf(CS timebuf + len, sizeof(timebuf)-len,
	    "%02u ", (uint)lp->tm_mday);
	  len += Ustrftime(timebuf + len, sizeof(timebuf) - len,
	    "%b %Y %H:%M:%S", lp);
	  (void) snprintf(CS timebuf + len, sizeof(timebuf)-len,
	    " %+03d%02d", diff_hour, diff_min);
	  }
	  break;
	}
      }
    break;
  }

return timebuf;
}

/* End of tod.c */
