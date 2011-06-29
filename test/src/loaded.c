/* This is a test function for dynamic loading in Exim expansions. It uses the
number of arguments to control the result. */

/* These lines are taken from local_scan.h in the Exim source: */

/* ========================================================================== */
/* Return codes from the support functions lss_match_xxx(). These are also the
codes that dynamically-loaded ${dlfunc functions must return. */

#define  OK            0          /* Successful match */
#define  DEFER         1          /* Defer - some problem */
#define  FAIL          2          /* Matching failed */
#define  ERROR         3          /* Internal or config error */

/* Extra return code for ${dlfunc functions */

#define  FAIL_FORCED   4          /* "Forced" failure */
/* ========================================================================== */


int dltest(unsigned char **yield, int argc, unsigned char *argv[])
{
switch (argc)
  {
  case 0:
  return ERROR;

  case 1:
  *yield = argv[0];
  return OK;

  case 2:
  *yield = (unsigned char *)"yield FAIL_FORCED";
  return FAIL_FORCED;

  default:
  *yield = (unsigned char *)"yield FAIL";
  return FAIL;
  }
}
