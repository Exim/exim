/* This is a baby program that is run as root from the runtest script. It is
passed the Exim uid and gid as arguments, and the name of a file in the
test-suite directory. It gives up all supplementary groups, changes to the
given uid/gid, and then tries to read the file. The yield is 0 if that is
successful, and non-zero otherwise (use different values to aid debugging). See
comments in the exim.c source file about the use of setgroups() for getting rid
of extraneous groups. */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include <stdio.h>


int main(int argc, char **argv)
{
int fd;
gid_t group_list[10];
struct passwd *pw = getpwnam(argv[2]);
struct group *gr = getgrnam(argv[3]);

if (pw == NULL) return 1;
if (gr == NULL) return 2;
if (setgroups(0, NULL) != 0 && setgroups(1, group_list) != 0) return 4;
if (setgid(gr->gr_gid) != 0) return 5;
if (setuid(pw->pw_uid) != 0) return 6;

fd = open(argv[1], O_RDONLY);
if (fd < 0) return 7;

close(fd);
return 0;
}

/* End */
