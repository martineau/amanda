#!@PERL@ 
# Copyright (c) 2005-2008 Zmanda Inc.  All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
#
# Contact information: Zmanda Inc., 465 S Mathlida Ave, Suite 300
# Sunnyvale, CA 94086, USA, or: http://www.zmanda.com

use lib '@amperldir@';
use strict;
use Getopt::Long;

package Amanda::Application::Amndmp;
use base qw(Amanda::Application);
use File::Copy;
use File::Path;
use IPC::Open2;
use IPC::Open3;
use Sys::Hostname;
use Symbol;
use IO::Handle;
use Amanda::Constants;
use Amanda::Config qw( :init :getconf  config_dir_relative );
use Amanda::Debug qw( :logging );
use Amanda::Paths;
use Amanda::Util qw( :constants :quoting);

sub new {
    my $class = shift;
    my ($config, $host, $disk, $device, $level, $index, $message, $collection, $record, $calcsize, $gnutar_path, $passfile, $ndmphost, $port, $bu_type) = @_;
    my $self = $class->SUPER::new($config);

    if (defined $gnutar_path) {
	$self->{gnutar}     = $gnutar_path;
    } else {
	$self->{gnutar}     = $Amanda::Constants::GNUTAR;
    }

    $self->{config}           = $config;
    $self->{host}             = $host;
    $self->{disk}             = $disk;
    if (defined $device) {
	$self->{device}       = $device;
    } else {
	$self->{device}       = $disk;
    }

    $self->{level}            = [ @{$level} ];
    $self->{index}            = $index;
    $self->{message}          = $message;
    $self->{collection}       = $collection;
    $self->{record}           = $record;
    $self->{calcsize}         = $calcsize;
    $self->{passfile}         = $passfile;
    $self->{ndmphost}         = $ndmphost;
    $self->{port}             = $port;
    $self->{bu_type}          = $bu_type;

    return $self;
}


# Read $self->{passfile} file.
# on entry:
#   $self->{ndmphost}
#   $self->{device}
# on exit:
#   $self->{username} = password
#   $self->{password} = password
#
# file format is:
# "NDMPHOST" "DEVICE" "USERNAME" "PASSWORD"
#
sub findpass {
    my $self = shift;

    my $passfile;
    my $line;

    $self->{username} = undef;
    $self->{password} = undef;

    if (open($passfile, $self->{passfile}) == 0) {
	$self->print_to_server_and_die($self->{action},"cannot open password file '$self->{passfile}': $!", $Amanda::Script_App::ERROR);
    }

    while ($line = <$passfile>) {
	chomp $line;
	next if $line =~ /^#/;
	my ($host, $device, $password, $username, $extra);
	($host, $device) = Amanda::Util::skip_quoted_string($line);
	if ($device) {
	    ($device, $username) = Amanda::Util::skip_quoted_string($device);
	}
	if ($username) {
	    ($username, $password) = Amanda::Util::skip_quoted_string($username);
	}
	if ($password) {
	    ($username, $extra) = Amanda::Util::skip_quoted_string($username);
	}
	if ($extra) {
	    debug("Trailling characters ignored in passfile line");
	}
	$host = Amanda::Util::unquote_string($host);
	$device = Amanda::Util::unquote_string($device);
	$password = Amanda::Util::unquote_string($password);
	$username = Amanda::Util::unquote_string($username);
	if (defined $host &&
	    ($host eq '*' || $host eq $self->{ndmphost}) &&
	    defined $device &&
	    ($device eq '*' || $device eq $self->{device})) {
	    $self->{username} = $username;
	    $self->{password} = $password;
	    close($passfile);
	    return;
	}
    }
    close($passfile);

    $self->print_to_server_and_die($self->{action},"Cannot find password for host $self->{ndmphost} and device $self->{device} in $self->{passfile}", $Amanda::Script_App::ERROR);
}

sub command_support {
    my $self = shift;

    print "CONFIG YES\n";
    print "HOST YES\n";
    print "DISK YES\n";
    print "MAX-LEVEL 9\n";
    print "INDEX-LINE YES\n";
    print "INDEX-XML NO\n";
    print "MESSAGE-LINE YES\n";
    print "MESSAGE-XML NO\n";
    print "RECORD YES\n";
    print "COLLECTION NO\n";
    print "MULTI-ESTIMATE NO\n";
    print "CALCSIZE NO\n";
    print "CLIENT-ESTIMATE NO\n";
}

sub command_selfcheck {
    my $self = shift;

    $self->{action} = 'check';

    #check binary

    if (!defined $self->{disk} || !defined $self->{device}) {
	return;
    }
    $self->findpass();

    print "OK " . $self->{disk} . "\n";
    print "OK " . $self->{device} . "\n";

    # try to connect

    #check statefile
    #check amdevice
}

sub command_estimate {
    my $self = shift;

    $self->{action} = 'estimate';
    $self->findpass();
}

sub output_size {
   my($level) = shift;
   my($size) = shift;
   if($size == -1) {
      print "$level -1 -1\n";
      #exit 2;
   }
   else {
      my($ksize) = int $size / (1024);
      $ksize=32 if ($ksize<32);
      print "$level $ksize 1\n";
   }
}

sub command_backup {
    my $self = shift;

    $self->{action} = 'backup';

    my $level = $self->{level}[0];
    my $mesgout_fd;
    open($mesgout_fd, '>&=3') || die();
    $self->{mesgout} = $mesgout_fd;

    $self->findpass();

    my ($index_rdr, $index_wtr);
    $^F=20;
    pipe($index_rdr, $index_wtr);
    my $data_fd;
    open $data_fd, ">&1";
    $^F=2;
    
    my($wtr, $rdr, $err);
    $err = Symbol::gensym;
    my $pid = open3($wtr, $rdr, $err, "-");
    if ($pid == 0) {
	#child
	close(0);
	my $amndmp_backup = $Amanda::Paths::amlibexecdir . "/amndmp_backup";
	my @ARGV = ();
	my $D = $self->{ndmphost};
	$D .= ":" . $self->{port} if ($self->{port});
	$D .= "/m4," . $self->{username} . "," . $self->{password};
	push @ARGV, $amndmp_backup,
                    "-L", "/home/martineau/tmp/aa", "-d9",
                    "-c",
                    "-D", $D,
                    "-T.",
                    "-f", fileno($data_fd),
                    "-I", fileno($index_wtr),
                    "-E", "LEVEL=" . $level,
                    "-C", $self->{device};
	if ($self->{bu_type}) {
	    push @ARGV, "-B", $self->{bu_type};
	}
	my $line = "Execute: " . join(" ", @ARGV);
	debug($line);
	exec {$amndmp_backup} @ARGV;
	exit;
    }
    close($index_wtr);
    close(1);
    close($data_fd);

    my $ksize = -1;

    #index process 
    if (defined($self->{index})) {
	my $filename;
	my %path;
	my $indexout_fd;
	open($indexout_fd, '>&=4') || die();
	while(<$index_rdr>) {
	    chomp;
	    debug("index: $_");
	    if (/^CM .*\/(.*)K$/) {
		$ksize = $1;
		debug("size: ". $ksize);
	    } elsif (/^DHf (.*) UNIX f(.)/) {
		$filename = "/$1";
		$filename .= '/' if ($1 ne '' && $2 eq 'd');
		print $indexout_fd "$filename\n";
		debug("iline: ". "$filename");
	    } elsif (/DHr (\d+)/) {
		$path{$1} = '';
		debug("path{$1} = $path{$1}");
	    } elsif (/DHd (\d+) (.+) UNIX (\d+)/) {
		if ($2 ne '.' && $2 ne '..') {
		    $path{$3} = $path{$1} . '/' . $2;
		    debug("path{$3} = $path{$3}");
		} else {
		    debug("ignore");
		}
	    } elsif (/DHn (\d+) UNIX f(.) /) {
		$filename = $path{$1};
		$filename .= '/' if ($2 eq 'd');
		print $indexout_fd "$filename\n";
		debug("iline: ". "$filename");
	    }
	}
	close($index_rdr);
	close($indexout_fd);
    }

    while (<$err>) {
	chomp;
	$self->print_to_server($self->{action}, "amndmp: $_",
			       $Amanda::Script_App::ERROR);
    }
    while (<$rdr>) {
	chomp;
	if (/Operation ended OKAY/) {
	} else {
	    $self->print_to_server($self->{action}, "amndmp: $_",
			           $Amanda::Script_App::ERROR);
	}
    }

    $ksize = 1000 if ($ksize <= 0);
    if ($ksize >= 0) {
	if ($ksize < 32) {
	    $ksize = 32;
	}
	print $mesgout_fd "sendbackup: size $ksize\n";
	print $mesgout_fd "sendbackup: end\n";
    }

    waitpid $pid, 0;
    if ($? != 0) {
	$self->print_to_server_and_die($self->{action},
				       "amndmp_backup returned error",
				       $Amanda::Script_App::ERROR);
    }
    exit 0;
}

sub command_restore {
    my $self = shift;
    my @cmd = ();

    $self->{restore} = 'backup';
    $self->findpass();

    my $amndmp_backup = $Amanda::Paths::amlibexecdir . "/amndmp_backup";
    my $D = $self->{ndmphost};
    $D .= ":" . $self->{port} if ($self->{port});
    $D .= "/m4," . $self->{username} . "," . $self->{password};
    push @cmd, $amndmp_backup,
               "-L", "/home/martineau/tmp/amndmp.extract", "-d9",
               "-x",
               "-D", $D,
               "-T.",
               "-f", "0",
               "-E", "FILESYSTEM=" . $self->{device},
               "-E", "PREFIX=" . $self->{device},
	       ;
#               "-C", "/vol/vol2/recup";
#               "-C", "/export/NDMP-target/restore";
    if ($self->{bu_type}) {
	push @cmd, "-B", $self->{bu_type};
    }

    my $restore_all = 0;
    for(my $i=1;defined $ARGV[$i]; $i++) {
	my $param = $ARGV[$i];
	if($param eq '.') {
	    $restore_all = 1;
	    # Add no -F argument
	    push @cmd, "-F", '/';
	}
    }
    if ($restore_all == 0) {
	for(my $i=1;defined $ARGV[$i]; $i++) {
	    my $param = $ARGV[$i];
	    $param =~ s/^\.\///;		# remove leading ./
	    push @cmd, "-F", $param;
	}
    }

    my $line = "Execute: " . join(" ", @cmd);
    debug($line);
    my $err = Symbol::gensym;
    my $pid = open3('<&STDIN', '>&STDOUT', $err, @cmd);
    while (<$err>) {
	next if (/SESS .* Warning: No -J input index\?$/);
	printf STDERR $_;
    }
    waitpid($pid, 0); 
    exit $?;
}

package main;

sub usage {
    print <<EOF;
Usage: amndmp <command> --config=<config> --host=<host> --disk=<disk> --device=<device> --level=<level> --index=<yes|no> --message=<text> --collection=<no> --record=<yes|no> --calcsize.
EOF
    exit(1);
}

my $opt_version;
my $opt_config;
my $opt_host;
my $opt_disk;
my $opt_device;
my @opt_level;
my $opt_index;
my $opt_message;
my $opt_collection;
my $opt_record;
my $opt_calcsize;
my $opt_gnutar_path;
my $opt_passfile;
my $opt_ndmphost;
my $opt_port;
my $opt_bu_type;

Getopt::Long::Configure(qw{bundling});
GetOptions(
    'version'            => \$opt_version,
    'config=s'           => \$opt_config,
    'host=s'             => \$opt_host,
    'disk=s'             => \$opt_disk,
    'device=s'           => \$opt_device,
    'level=s'            => \@opt_level,
    'index=s'            => \$opt_index,
    'message=s'          => \$opt_message,
    'collection=s'       => \$opt_collection,
    'record'             => \$opt_record,
    'calcsize'           => \$opt_calcsize,
    'gnutar_path=s'      => \$opt_gnutar_path,
    'passfile=s'         => \$opt_passfile,
    'ndmphost=s'         => \$opt_ndmphost,
    'port=s'             => \$opt_port,
    'bu-type=s'          => \$opt_bu_type,
) or usage();

if (defined $opt_version) {
    print "amndmp-" . $Amanda::Constants::VERSION , "\n";
    exit(0);
}

my $application = Amanda::Application::Amndmp->new($opt_config, $opt_host, $opt_disk, $opt_device, \@opt_level, $opt_index, $opt_message, $opt_collection, $opt_record, $opt_calcsize, $opt_gnutar_path, $opt_passfile, $opt_ndmphost, $opt_port, $opt_bu_type);

$application->do($ARGV[0]);
