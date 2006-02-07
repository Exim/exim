# Perl script to print all lines starting "-local" from -H files

opendir(DIR, "spool/input") || die "failed to opendir spool/input\n";
@spools = readdir(DIR);
closedir(DIR);

foreach $f (@spools)
  {
  next if $f !~ /-H$/; 
  open(IN, "<spool/input/$f") || die "failed to open spool/input/$f\n";
  print "$f\n";
  while(<IN>) { print if /^-local/; }
  close(IN);
  }
  
####   
