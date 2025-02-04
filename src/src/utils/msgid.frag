# Start msgid.frag
# Copyright (c) The Exim Maintainers 2025
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Regex patterns for exim message-id

# Simple matching

my $b62 = "[[:alnum:]]";

my $msgid_sec_re = "${b62}{6}";
my $msgid_pid_new_re = "${b62}{11}";
my $msgid_pid_old_re = "${b62}{6}";
my $msgid_frc_new_re = "${b62}{4}";
my $msgid_frc_old_re = "${b62}{2}";

my $msgid_new_re = "$msgid_sec_re-$msgid_pid_new_re-$msgid_frc_new_re";
my $msgid_old_re = "$msgid_sec_re-$msgid_pid_old_re-$msgid_frc_old_re";
my $msgid_re =     "(?:$msgid_new_re|$msgid_old_re)";


# Match with content submatches
# - requires variables seconds, pid, fractions

my $msgid_sec_cap_re = "(?<seconds>$msgid_sec_re)";
my $msgid_pid_cap_re = "(?<pid>(?:$msgid_pid_new_re|$msgid_pid_old_re))";
my $msgid_frc_cap_re = "(?<fractions>(?:$msgid_frc_new_re|$msgid_frc_old_re))";

my $msgid_cap_re = "(?:$msgid_sec_cap_re-$msgid_pid_cap_re-$msgid_frc_cap_re)";

# End msgid.frag
