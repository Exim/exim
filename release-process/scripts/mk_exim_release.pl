#!/usr/bin/perl
#
# $Cambridge: exim/release-process/scripts/mk_exim_release.pl,v 1.1 2010/06/03 12:00:38 nm4 Exp $
#
use strict;
use warnings;
use Carp;
use File::Copy;
use File::Spec;
use File::Path;
use Getopt::Long;
use Pod::Usage;

my $debug   = 0;
my $verbose = 0;

# ------------------------------------------------------------------

sub get_and_check_version {
    my $release = shift;

    # make sure this looks like a real release version
    # which should (currently) be 4.xx
    unless ( $release =~ /^(4\.\d\d(?:_RC\d+)?)$/ ) {
        croak "The given version number does not look right - $release";
    }
    return $1;    # untainted here...
}

# ------------------------------------------------------------------

sub build_cvs_tag {
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

    mkpath( $context->{directory}, { verbose => ( $verbose || $debug ) } );
}

# ------------------------------------------------------------------

sub export_cvs_tree {
    my $context = shift;

    # build CVS command
    my @cmd = ( 'cvs', '-d', $context->{cvsroot}, '-Q', 'export', '-r', $context->{tag}, $context->{pkgname}, );

    # run cvs command
    print( "Running: ", join( ' ', @cmd ), "\n" ) if ($verbose);
    system(@cmd) == 0 || croak "Export failed";
}

# ------------------------------------------------------------------

sub build_documentation {
    system("cd exim/exim-doc/doc-docbook && ./OS-Fixups && make everything") == 0
      || croak "Doc build failed";
}

# ------------------------------------------------------------------

sub move_text_docs_into_pkg {
    my $context = shift;

    my $old_docdir = 'exim/exim-doc/doc-docbook';
    my $new_docdir = File::Spec->catdir( $context->{pkgdir}, 'doc' );
    mkpath( $new_docdir, { verbose => ( $verbose || $debug ) } );

    # move generated documents from docbook stuff
    foreach my $file (qw/exim.8 spec.txt filter.txt/) {
        move( File::Spec->catfile( $old_docdir, $file ), File::Spec->catfile( $new_docdir, $file ) );
    }

    # move text documents across
    foreach my $file ( glob( File::Spec->catfile( 'exim/exim-doc/doc-txt', '*' ) ) ) {

        # skip a few we dont want
        my $fn = ( File::Spec->splitpath($file) )[2];
        next
          if ( ( $fn eq 'ABOUT' )
            || ( $fn eq 'ChangeLog.0' )
            || ( $fn eq 'test-harness.txt' ) );
        move( $file, File::Spec->catfile( $new_docdir, $fn ) );
    }
}

# ------------------------------------------------------------------

sub build_pspdfinfo_directory {
    my $context = shift;

    ##foreach my $format (qw/pdf postscript texinfo info/) {
    foreach my $format (qw/pdf postscript/) {
        my $dir = sprintf( 'exim-%s-%s', $format, $context->{release} );
        my $target = File::Spec->catdir( $dir, 'doc' );
        mkpath( $target, { verbose => ( $verbose || $debug ) } );

        # move documents across
        foreach my $file (
            glob(
                File::Spec->catfile(
                    'exim/exim-doc/doc-docbook',
                    (
                        ( $format eq 'postscript' )
                        ? '*.ps'
                        : ( '*.' . $format )
                    )
                )
            )
          )
        {
            my $fn = ( File::Spec->splitpath($file) )[2];
            move( $file, File::Spec->catfile( $target, $fn ) );
        }
    }
}

# ------------------------------------------------------------------

sub build_html_directory {
    my $context = shift;

    my $dir = sprintf( 'exim-%s-%s', 'html', $context->{release} );
    my $target = File::Spec->catdir( $dir, 'doc', 'html' );
    mkpath( $target, { verbose => ( $verbose || $debug ) } );

    # move documents across
    move( File::Spec->catdir( 'exim/exim-doc/doc-docbook', 'spec_html' ), File::Spec->catdir( $target, 'spec_html' ) );
    foreach my $file ( glob( File::Spec->catfile( 'exim/exim-doc/doc-docbook', '*.html' ) ) ) {
        my $fn = ( File::Spec->splitpath($file) )[2];
        move( $file, File::Spec->catfile( $target, $fn ) );
    }
}

# ------------------------------------------------------------------

sub build_main_package_directory {
    my $context = shift;

    # initially we move the exim-src directory to the new directory name
    my $pkgdir = sprintf( 'exim-%s', $context->{release} );
    $context->{pkgdir} = $pkgdir;
    rename( 'exim/exim-src', $pkgdir ) || croak "Rename of src dir failed - $!";

    # add Local subdirectory
    my $target = File::Spec->catdir( $pkgdir, 'Local' );
    mkpath( $target, { verbose => ( $verbose || $debug ) } );

    # now add the text docs
    move_text_docs_into_pkg($context);
}

# ------------------------------------------------------------------

sub build_package_directories {
    my $context = shift;

    build_main_package_directory($context);
    build_pspdfinfo_directory($context);
    build_html_directory($context);
}

# ------------------------------------------------------------------

sub create_tar_files {
    my $context = shift;

    foreach my $dir ( glob( 'exim*-' . $context->{release} ) ) {
        system("tar cfz ${dir}.tar.gz ${dir}");
        system("tar cfj ${dir}.tar.bz2 ${dir}");
    }
}

# ------------------------------------------------------------------
{
    my $man;
    my $help;
    my $context = {
        cvsroot  => ':ext:nm4@vcs.exim.org:/home/cvs',
        pkgname  => 'exim',
        orig_dir => File::Spec->curdir(),
    };
    my $delete;
    $ENV{'PATH'} = '/opt/local/bin:' . $ENV{'PATH'};

    unless (
        GetOptions(
            'directory=s' => \$context->{directory},
            'cvsroot=s'   => \$context->{cvsroot},
            'verbose!'    => \$verbose,
            'debug!'      => \$debug,
            'help|?'      => \$help,
            'man!'        => \$man,
            'delete!'     => \$delete,
        )
      )
    {
        pod2usage( -exitval => 1, -verbose => 0 );
    }
    pod2usage(0) if $help;
    pod2usage( -verbose => 2 ) if $man;

    $context->{release} = get_and_check_version(shift);
    $context->{tag}     = build_cvs_tag($context);
    deal_with_working_directory( $context, $delete );
    chdir( $context->{directory} ) || die;
    export_cvs_tree($context);
    build_documentation($context);
    build_package_directories($context);
    create_tar_files($context);
}

1;

__END__

=head1 NAME

mk_exim_release.pl - Build an exim release

=head1 SYNOPSIS

mk_exim_release.pl [options] version

 Options:
   --debug             force debug mode (SQL Trace)
   --verbose           force verbose mode
   --help              display this help and exits
   --man               displays man page
   --directory=dir     dir to package
   --cvsroot=s         CVS root spec
   --delete            Delete packaging directory at start

=head1 OPTIONS

=over 4

=item B<--debug>

Forces debug mode cause all SQL statements generated by L<DBIx::Class>
to be output.

=item B<--verbose>

Force verbose mode - currently this has no effect

=item B<--help>

Display help and exits

=item B<--man>

Display man page

=back

=head1 DESCRIPTION

Builds an exim release.

Starting in an empty directory, with the CVS repo already tagged
for release, build docs, build packages etc.

NB The CVS root spec is embedded in the script or can be given via
the I<--cvsroot> parameter

Parameter is the version number to build as - ie 4.72 4.72RC1 etc

=head1 AUTHOR

Nigel Metheringham <Nigel.Metheringham@dev.intechnology.co.uk>

=head1 COPYRIGHT

Copyright 2009 Someone. All rights reserved.

=cut
