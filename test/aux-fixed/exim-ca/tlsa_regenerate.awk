# The commands beaing read-out and run assume CWD is the test/ directory
#
# start collecting a command to run
/^; TLSA_AUTOGEN$/ { active = 1; print; next; }
#
# keep appending to the command while there is a continuation-line marker (trailing backslash)
active==1 && /^;/ { print;
		    if (NF > 1)
		      {
		      cmdstr = cmdstr " " substr($0, 2);
		      if (cmdstr ~ /\\$/)
			cmdstr = substr(cmdstr, 1, length(cmdstr)-1);
		      else
			active = 2;
		      }
		    next;
		  }
#
# apply the command to the next TLSA linem and go quiescent
active==2 && /TLSA/ { cmdstr | getline cmdres;
		      if (NF == 7)
			{ printf("%s %s %s %s %s %s %s\n", $1, $2, $3, $4, $5, $6, cmdres); }
		      else
			{ printf("%s %s %s %s %s %s\n",    $1, $2, $3, $4, $5, cmdres); }
		      cmdstr = "";
		      active = 0;
		      next;
		    }
#
# just copy other lines
{ print; }
