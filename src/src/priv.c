#include "exim.h"
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

static enum {
  PRIV_DROPPING, PRIV_DROPPED,
  PRIV_RESTORING, PRIV_RESTORED
} priv_state = PRIV_RESTORED;


static uid_t priv_euid;
static gid_t priv_egid;
static gid_t priv_groups[EXIM_GROUPLIST_SIZE + 1];
static int priv_ngroups;

/* Inspired by OpenSSH's temporarily_use_uid(). Thanks! */

void
priv_drop_temp(const uid_t temp_uid, const gid_t temp_gid)
{
if (priv_state != PRIV_RESTORED)
  log_write(0, LOG_PANIC_DIE, "priv_drop_temp: unexpected priv_state %d != %d", priv_state, PRIV_RESTORED);

priv_state = PRIV_DROPPING;

priv_euid = geteuid();
if (priv_euid == root_uid)
  {
  priv_egid = getegid();
  priv_ngroups = getgroups(nelem(priv_groups), priv_groups);
  if (priv_ngroups < 0)
    log_write(0, LOG_PANIC_DIE, "getgroups: %s", strerror(errno));

  if (priv_ngroups > 0 && setgroups(1, &temp_gid) != 0)
    log_write(0, LOG_PANIC_DIE, "setgroups: %s", strerror(errno));
  if (setegid(temp_gid) != 0)
    log_write(0, LOG_PANIC_DIE, "setegid(%d): %s", temp_gid, strerror(errno));
  if (seteuid(temp_uid) != 0)
    log_write(0, LOG_PANIC_DIE, "seteuid(%d): %s", temp_uid, strerror(errno));

  if (geteuid() != temp_uid)
    log_write(0, LOG_PANIC_DIE, "getdeuid() != %d", temp_uid);
  if (getegid() != temp_gid)
    log_write(0, LOG_PANIC_DIE, "getegid() != %d", temp_gid);
  }

priv_state = PRIV_DROPPED;
}

/* Inspired by OpenSSH's restore_uid(). Thanks! */

void
priv_restore(void)
{
if (priv_state != PRIV_DROPPED)
  log_write(0, LOG_PANIC_DIE, "priv_restore: unexpected priv_state %d != %d", priv_state, PRIV_DROPPED);
priv_state = PRIV_RESTORING;

if (priv_euid == root_uid)
  {
  if (seteuid(priv_euid) != 0)
    log_write(0, LOG_PANIC_DIE, "seteuid(%d): %s", priv_euid, strerror(errno));
  if (setegid(priv_egid) != 0)
    log_write(0, LOG_PANIC_DIE, "setegid(%d): %s", priv_egid, strerror(errno));
  if (priv_ngroups > 0 && setgroups(priv_ngroups, priv_groups) != 0)
    log_write(0, LOG_PANIC_DIE, "setgroups: %s", strerror(errno));

  if (geteuid() != priv_euid)
    log_write(0, LOG_PANIC_DIE, "getdeuid() != %d", priv_euid);
  if (getegid() != priv_egid)
    log_write(0, LOG_PANIC_DIE, "getdegid() != %d", priv_egid);
  }

priv_state = PRIV_RESTORED;
}
