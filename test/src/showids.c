/* $Cambridge: exim/test/src/showids.c,v 1.1 2006/02/06 16:24:05 ph10 Exp $ */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(void)
{
int count, i;
gid_t grouplist[100];

printf("uid=%d gid=%d euid=%d egid=%d\n",
  getuid(), getgid(), geteuid(), getegid());

/* Can no longer use this because on different systems, the supplemental
groups will be different. */

#ifdef NEVER
printf("supplemental groups: ");
count = getgroups(100, grouplist);
for (i = 0; i < count; i++) printf("%d ", grouplist[i]);
printf("\n");
#endif

return 0;
}
