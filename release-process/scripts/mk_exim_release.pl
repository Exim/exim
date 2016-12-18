#!/usr/bin/env perl
# Copyright (c) The Exim Maintainers 2016

use strict;
use warnings;
use Carp;
use File::Copy;
use File::Spec;
use File::Path;
use File::Temp;
use FindBin;
use Getopt::Long;
use IO::File;
use Pod::Usage;

my $debug   = 0;
my $verbose = 0;

# ------------------------------------------------------------------

sub get_and_check_version {
    my $release = shift;
    my $context = shift;

    # make sure this looks like a real release version
    # which should (currently) be 4.xx[.y] or 4.xx[.y]_RCx
    unless ( $release =~ /^(?<release>(?<major>4\.\d\d)(?:\.(?<minor>\d+))?(?:_RC\d+)?)$/ ) {
        croak "The given version number does not look right - $release";
    }
    $context->{release}  = $+{release};
    $context->{major} = $+{major};
    $context->{minor} = $+{minor};

    ($context->{trelease} = $+{release}) =~ s/_RC\d+//;
}

# ------------------------------------------------------------------

sub build_tag {
    my $context = shift;

    # The CVS tag consists of exim-$version where $version
    # is the version number with . replaced with _
    my $modversion = $context->{release};
    $modversion =~ tr/0-9RC/_/cs;

    return sprintf( 'exim-%s', $modversion );
}

# ------------------------------------------------------------------

sub deal_with_working_directory {
    my $context = shift;
    my $delete  = shift;

    # Set default directory
    $context->{directory} ||= File::Spec->rel2abs( sprintf( 'exim-packaging-%s', $context->{release} ) );
    my $directory = $context->{directory};

    # ensure the working directory is not in place
    if ( -d $directory ) {
        if ($delete) {
            print "Deleting existing $directory\n" if ($verbose);
            rmtree( $directory, { verbose => $debug } );
        }
        if ( -d $directory ) {
            croak "Working directory $directory exists";
        }
    }

    # create base directory
    mkpath( $context->{directory}, { verbose => ( $verbose || $debug ) } );

    # set and create subdirectories
    foreach (qw(release_tree pkgs pkgdirs docbook tmp)) {
        $context->{$_} = File::Spec->catdir( $context->{directory}, $_ );
        mkpath( $context->{$_}, { verbose => ( $verbose || $debug ) } );
    }
}

# ------------------------------------------------------------------

sub export_git_tree {
    my $context = shift;

    # build git command
    my $archive_file = sprintf( '%s/%s-%s.tar', $context->{tmp}, $context->{pkgname}, $context->{release} );
    $context->{tmp_archive_file} = $archive_file;
    my @cmd = ( 'git', 'archive', '--format=tar', "--output=$archive_file", $context->{tag} );
    # run git command
    print( "Running: ", join( ' ', @cmd ), "\n" ) if ($verbose);
    system(@cmd) == 0 || croak "Export failed";
}

# ------------------------------------------------------------------

sub unpack_tree {
    my $context = shift;

    die "Cannot see archive file\n" unless ( -f $context->{tmp_archive_file} );
    my @cmd = ( 'tar', 'xf', $context->{tmp_archive_file}, '-C', $context->{release_tree} );

    # run  command
    print( "Running: ", join( ' ', @cmd ), "\n" ) if ($verbose);
    system(@cmd) == 0 || croak "Unpack failed";
}

# ------------------------------------------------------------------

sub make_version_script {
    my $context = shift;

    my $variant = substr( $context->{release}, length($context->{trelease}) );
    if ( $context->{release} ne $context->{trelease} . $variant ) {
        die "Broken version numbering, I'm buggy";
    }

    my $srcdir    = File::Spec->catdir( $context->{release_tree}, 'src', 'src' );
    chdir $srcdir or die "chdir $srcdir: $!\n";

    if ( -f "version.sh" ) {
        print( "WARNING: version.sh already exists - leaving it in place\n" );
        return;
    }

    # Currently (25. Feb. 2016) the mk_exim_release.pl up to now can't
    # deal with security releases.!? So we need a current
    # mk_exim_release.pl. But if we use a current (master), the
    # reversion script returns wrong version info (it's running inside
    # the Git tree and uses git --describe, which always returns the
    # current version of master.) I do not want to change the old
    # reversion scripts (in 4.86.1, 4.85.1).
    #
    # Thus we've to provide the version.sh, based on the info we have
    # about the release. If reversion finds this, it doesn't try to find
    # it's own way to get a valid version number from the git.
    open(my $v, '>', 'version.sh') or die "Can't open '>version.sh' $!\n";
    print {$v} <<__;
# initial version automatically generated from $0
EXIM_RELEASE_VERSION=$context->{major}
EXIM_VARIANT_VERSION=@{[$context->{minor}?'_'.$context->{minor}:'']}
EXIM_COMPILE_NUMBER=0
__
    close($v);
    unlink 'version.h';
    return;

    # Later, if we get the reversion script fixed, we can call it again.
    # For now (25. Feb. 2016) we'll leave it unused.
    my @cmd = ("../scripts/reversion", "release", $context->{tag});
    print( "Running: ", join( ' ', @cmd ), "\n" ) if ($verbose);
    system(@cmd) == 0 || croak "reversion failed";

    unlink "version.h";

    -f "version.sh" or die "failed to create version.sh";
}

# ------------------------------------------------------------------

sub build_html_documentation {
    my $context = shift;

    my $genpath   = $context->{webgen_base} . '/script/gen.pl';
    my $templates = $context->{webgen_base} . '/templates';
    my $dir       = File::Spec->catdir( $context->{release_tree}, 'html' );
    my $spec      = File::Spec->catfile( $context->{docbook}, 'spec.xml' );
    my $filter    = File::Spec->catfile( $context->{docbook}, 'filter.xml' );

    mkdir($dir);

    my @cmd = (
        $genpath,   '--spec',    $spec,                '--filter',
        $filter,    '--latest',  $context->{trelease}, '--tmpl',
        $templates, '--docroot', $dir,                 '--localstatic'
    );
    push @cmd, '--verbose' if $verbose or $debug;

    print "Executing ", join( ' ', @cmd ), "\n";
    system(@cmd);

    # move directory into right place
    my $sourcedir = File::Spec->catdir( $context->{docbook}, 'filter.xml' );

    rename(
        File::Spec->catdir( $dir,                sprintf( 'exim-html-%s', $context->{trelease} ) ),
        File::Spec->catdir( $context->{pkgdirs}, sprintf( 'exim-html-%s', $context->{release} ) )
    );
}

# ------------------------------------------------------------------

sub copy_docbook_files {
    my $context = shift;

    # where the generated docbook files can be found
    my $docdir = File::Spec->catdir( $context->{release_tree}, 'doc', 'doc-docbook' );

    # where the website docbook source dir is - push files to here
    my $webdir = File::Spec->catdir( $context->{webgen_base}, 'docbook', $context->{trelease} );
    mkpath( $webdir, { verbose => ( $verbose || $debug ) } );

    foreach my $file ( 'spec.xml', 'filter.xml' ) {
        my $from  = File::Spec->catfile( $docdir,             $file );
        my $to    = File::Spec->catfile( $context->{docbook}, $file );
        my $webto = File::Spec->catfile( $webdir,             $file );
        copy( $from, $to );
        copy( $from, $webto );
    }
}

# ------------------------------------------------------------------

sub build_documentation {
    my $context = shift;

    my $docdir = File::Spec->catdir( $context->{release_tree}, 'doc', 'doc-docbook' );
    # documentation building gets the truncated release, without RC
    system("cd '$docdir' && ./OS-Fixups && $context->{make_cmd} EXIM_VER=$context->{trelease} everything") == 0
      || croak "Doc build failed";

    copy_docbook_files($context);
    build_html_documentation($context) if $context->{web};
}

# ------------------------------------------------------------------

sub move_text_docs_into_pkg {
    my $context = shift;

    my $old_docdir = File::Spec->catdir( $context->{release_tree}, 'doc', 'doc-docbook' );
    my $old_txtdir = File::Spec->catdir( $context->{release_tree}, 'doc', 'doc-txt' );
    my $new_docdir = File::Spec->catdir( $context->{eximpkgdir}, 'doc' );
    mkpath( $new_docdir, { verbose => ( $verbose || $debug ) } );

    # move generated documents from docbook stuff
    foreach my $file (qw/exim.8 spec.txt filter.txt/) {
        move( File::Spec->catfile( $old_docdir, $file ), File::Spec->catfile( $new_docdir, $file ) );
    }

    # move text documents across
    foreach my $file ( glob( File::Spec->catfile( $old_txtdir, '*' ) ) ) {

        # skip a few we dont want
        my $fn = ( File::Spec->splitpath($file) )[2];
        next
          if ( ( $fn eq 'ABOUT' )
            || ( $fn eq 'ChangeLog.0' )
            || ( $fn eq 'test-harness.txt' )
            # Debian issue re licensing of RFCs
            || ( $fn =~ /^draft-ietf-.*/ )
            || ( $fn =~ /^rfc.*/ )
             );
        move( $file, File::Spec->catfile( $new_docdir, $fn ) );
    }
}

# ------------------------------------------------------------------

sub build_pspdfinfo_directory {
    my $context = shift;

    ##foreach my $format (qw/pdf postscript texinfo info/) {
    foreach my $format (qw/pdf postscript/) {
        my $target = File::Spec->catdir( $context->{pkgdirs}, sprintf( 'exim-%s-%s', $format, $context->{release} ), 'doc' );
        mkpath( $target, { verbose => ( $verbose || $debug ) } );

        # move documents across
        foreach my $file (
            glob(
                File::Spec->catfile(
                    $context->{release_tree},
                    'doc',
                    'doc-docbook',
                    (
                        ( $format eq 'postscript' )
                        ? '*.ps'
                        : ( '*.' . $format )
                    )
                )
            )
          )
        {
            move( $file, File::Spec->catfile( $target, ( File::Spec->splitpath($file) )[2] ) );
        }
    }
}

# ------------------------------------------------------------------

sub build_main_package_directory {
    my $context = shift;

    # build the exim package directory path
    $context->{eximpkgdir} = File::Spec->catdir( $context->{pkgdirs}, sprintf( 'exim-%s', $context->{release} ) );

    # initially we move the exim-src directory to the new directory name
    rename( File::Spec->catdir( $context->{release_tree}, 'src' ), $context->{eximpkgdir} )
      || croak "Rename of src dir failed - $!";

    # add Local subdirectory
    mkpath( File::Spec->catdir( $context->{eximpkgdir}, 'Local' ), { verbose => ( $verbose || $debug ) } );

    # now add the text docs
    move_text_docs_into_pkg($context);
}

# ------------------------------------------------------------------

sub build_package_directories {
    my $context = shift;

    build_main_package_directory($context);
    build_pspdfinfo_directory($context) if $context->{build_docs};
}

# ------------------------------------------------------------------

sub do_cleanup {
    my $context = shift;

    print "Cleaning up\n" if ($verbose);
    chdir( $context->{directory} ) || die;
    rmtree( $context->{release_tree}, { verbose => $debug } );
    rmtree( $context->{docbook},      { verbose => $debug } );
    rmtree( $context->{pkgdirs},      { verbose => $debug } );
}

# ------------------------------------------------------------------

# We prefer gtar to tar if gtar exists in $PATH

sub fix_paths_tar {
    my $context = shift;
    my $tar = $context->{tar_cmd};

    return unless $tar eq 'tar';

    foreach my $d (File::Spec->path()) {
        my $p = File::Spec->catfile($d, 'gtar');
        if (-x $p) {
            $context->{tar_cmd} = $p;
            print "Switched tar command to: $p\n" if ($verbose);
            return;
        }
    }
}

# ------------------------------------------------------------------

sub create_tar_files {
    my $context = shift;

    my $pkgs    = $context->{pkgs};
    my $pkgdirs = $context->{pkgdirs};
    my $tar     = $context->{tar_cmd};
    if ($verbose) {
        foreach my $c (keys %{ $context->{compressors} }) {
            print "Compression: $c\t$context->{compressors}{$c}\n";
        }
    }

    foreach my $dir ( glob( File::Spec->catdir( $pkgdirs, ( 'exim*-' . $context->{release} ) ) ) ) {
        my $dirname = ( File::Spec->splitdir($dir) )[-1];
        if ($context->{compressors}{gzip}) {
            print "Creating: ${pkgs}/${dirname}.tar.gz\n" if ($verbose || $debug);
            system("$tar cf  ${pkgs}/${dirname}.tar.gz  --gzip  -C ${pkgdirs} ${dirname}")
        }
        if ($context->{compressors}{bzip2}) {
            print "Creating: ${pkgs}/${dirname}.tar.bz2\n" if ($verbose || $debug);
            system("$tar cf  ${pkgs}/${dirname}.tar.bz2 --bzip2 -C ${pkgdirs} ${dirname}")
        }
        if ($context->{compressors}{lzip}) {
            print "Creating: ${pkgs}/${dirname}.tar.lz\n" if ($verbose || $debug);
            system("$tar cf  ${pkgs}/${dirname}.tar.lz  --lzip  -C ${pkgdirs} ${dirname}")
        }
    }
}

# ------------------------------------------------------------------
{
    my $man;
    my $help;
    my $context = {
        pkgname     => 'exim',
        orig_dir    => File::Spec->curdir(),
        tmp_dir     => File::Temp->newdir(),
        webgen_base => "$FindBin::Bin/../../../exim-website",
        tar_cmd     => 'tar',
        make_cmd    => 'make',
        compressors => {
                gzip    => 1,
                bzip2   => 1,
                lzip    => 0,
        },
        build_docs   => 1,
        web          => 1,
    };
    my $delete;
    my $cleanup = 1;
    ##$ENV{'PATH'} = '/opt/local/bin:' . $ENV{'PATH'};

    unless (
        GetOptions(
            'directory=s'   => \$context->{directory},
            'webgen_base=s' => \$context->{webgen_base},
            'tar=s'         => \$context->{tar_cmd},
            'make=s'        => \$context->{make_cmd},
            'lzip!'         => \$context->{compressors}{lzip},
            'verbose!'      => \$verbose,
            'debug!'        => \$debug,
            'help|?'        => \$help,
            'man!'          => \$man,
            'delete!'       => \$delete,
            'cleanup!'      => \$cleanup,
            'build-docs!'   => \$context->{build_docs},
            'web!'          => \$context->{web},
        )
      )
    {
        pod2usage( -exitval => 1, -verbose => 0 );
    }
    pod2usage(0) if $help;
    pod2usage( -verbose => 2 ) if $man;

    get_and_check_version( shift, $context );
    fix_paths_tar($context);
    $context->{tag} = build_tag($context);
    deal_with_working_directory( $context, $delete );
    export_git_tree($context);
    chdir( $context->{directory} ) || die;
    unpack_tree($context);
    make_version_script($context);
    build_documentation($context) if $context->{build_docs};
    build_package_directories($context);
    create_tar_files($context);
    do_cleanup($context) if ($cleanup);
}

1;

__END__

=head1 NAME

mk_exim_release.pl - Build an exim release

=head1 SYNOPSIS

mk_exim_release.pl [options] version

 Options:
   --debug             force debug mode
   --verbose           force verbose mode
   --help              display this help and exits
   --man               displays man page
   --tar=cmd           command to use for tar
   --make=cmd          command to use for make
   --directory=dir     dir to package
   --no-lzip           do not create .tar.lz files
   --delete            Delete packaging directory at start
   --no-web            skip the website generation

=head1 OPTIONS

=over 4

=item B<--debug>

Forces debug mode.

=item B<--tar>

Use to override the path to the tar command; without this, will search for
gtar, and if not found use tar.  Need GNU tar for lzip, unless --no-lzip is
used.

=item B<--make>

Use to override the path/name of the make command.
Useful sometimes to force gmake.

=item B<--lzip>

Build the lzip tarballs.

=item B<--verbose>

Force verbose mode

=item B<--help>

Display help and exits

=item B<--man>

Display man page

=back

=head1 DESCRIPTION

Builds an exim release.

Starting in a populated git repo that has already been tagged for
release, build docs, build packages etc.

Parameter is the version number to build as - ie 4.72 4.72RC1, 4.86.1, etc

=head1 AUTHOR

Nigel Metheringham <Nigel.Metheringham@dev.intechnology.co.uk>

=head1 COPYRIGHT

Copyright 2010 Exim Maintainers. All rights reserved.

=cut
# vim: set sw=4 et :
