/* A program to check on open file descriptors. There are some weird options
for running it in Exim testing. If -q is given, make output suitable for
queryprogram. If -f is given, copy the input as for a transport filter. If -s
is given, add extra output from stat(). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>


/* The way of finding out the maximum file descriptor various between OS.
Most have sysconf(), but a few don't. */

#ifdef _SC_OPEN_MAX
  #define mac_maxfd (sysconf(_SC_OPEN_MAX) - 1)
#elif defined OPEN_MAX
  #define mac_maxfd (OPEN_MAX - 1)
#elif defined NOFILE
  #define mac_maxfd (NOFILE - 1)
#else
  #define mac_maxfd 255;    /* just in case */
#endif


int main(int argc, char **argv)
{
int fd;
int qpgm = 0;
int filter = 0;
int use_stat = 0;
struct stat statbuf;
char buffer[8192];
char *p = buffer;

while (argc > 1)
  {
  char *arg = argv[--argc];
  if (strcmp(arg, "-q") == 0) qpgm = 1;
  if (strcmp(arg, "-f") == 0) filter = 1;
  if (strcmp(arg, "-s") == 0) use_stat = 1;
  }

if (filter)
  {
  int len;
  while ((len = read(0, buffer, sizeof(buffer))) > 0)
    if (write(1, buffer, len) < 0)
	exit(1);
  }

p += sprintf(p, "max fd = %d\n", (int)mac_maxfd);

for (fd = 0; fd <= mac_maxfd; fd++)
  {
  int options = fcntl(fd, F_GETFD);
  if (options >= 0)
    {
    int status = fcntl(fd, F_GETFL);
    p += sprintf(p, "%3d opt=%d status=%X ", fd, options, status);
    switch(status & 3)
      {
      case 0: p += sprintf(p, "RDONLY");
      break;
      case 1: p += sprintf(p, "WRONLY");
      break;
      case 2: p += sprintf(p, "RDWR");
      break;
      }
    if (isatty(fd)) p += sprintf(p, " TTY");
    if ((status & 8) != 0) p += sprintf(p, " APPEND");

    if (use_stat && fstat(fd, &statbuf) >= 0)
      {
      p += sprintf(p, " mode=%o uid=%d size=%d", (int)statbuf.st_mode,
        (int)statbuf.st_uid, (int)statbuf.st_size);
      }

    p += sprintf(p, "\n");
    }
  else if (errno != EBADF)
    {
    p += sprintf(p, "%3d errno=%d %s\n", fd, errno, strerror(errno));
    }
  }

if (qpgm)
  {
  for (p = buffer; *p != 0; p++)
    if (*p == '\n') *p = ' ';
  printf("ACCEPT DATA=\"%s\"\n", buffer);
  }
else printf("%s", buffer);

exit(0);
}

/* End */
