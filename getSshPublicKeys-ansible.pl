#!/usr/bin/perl
#
# generates AuthorizedKeysFile output with ssh keys from LDAP accounts
# (C)2015 bli@censhare.de

use Encode;
use utf8;
use open ':encoding(utf8)';
binmode(STDOUT, ":utf8");
use File::Path qw(make_path remove_tree);
use Net::LDAP;
use Sys::Hostname;
use POSIX qw/strftime/;
use autodie;

usage() if  ($#ARGV=0);

# -CONFIG-
my $keyPath = "/root/tmp/keys";
my @validUsers = ('root', 'corpus', 'oracle', 'nagios', 'git', 'postgres');
# --------

my $arg = $ARGV[0];
my $hostname = $ARGV[1];
my ($ldapServer, $sAMAccountName, @demigods, $demigod, $member, @users, $user, $cn, $mail, $keys, $key);
my $ldapBase = "DC=int,DC=censhare,DC=com";
my $ldapFilterDemigods = "(&(sshPublicKey=*)(mail=*)(objectClass=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberof:1.2.840.113556.1.4.1941:=CN=ssh_demigods,OU=sshPublicKeys,OU=SystemAccess,OU=Groups,DC=int,DC=censhare,DC=com))";
my $ldapFilterUsers = "(&(sshPublicKey=*)(objectClass=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberof:1.2.840.113556.1.4.1941:=CN=ssh_$arg,OU=sshPublicKeys,OU=SystemAccess,OU=Groups,DC=int,DC=censhare,DC=com))";
my $ldapUser = 'nagios@int.censhare.com';
my $ldapPass = 'xs2LDAP4icinga';

while ($#ARGV>=0) {
  usage() if ($arg =~ "-h") || (not(grep /^$arg$/, @validUsers));
  last;
}

remove_tree($keyPath) if (-d $keyPath || -f $keyPath);
make_path($keyPath) or die( "Cannot create directory!\n" );
make_path($keyPath . "/" . $arg) or die( "Cannot create directory!\n" );
make_path($keyPath . "/demigods") or die( "Cannot create directory!\n" );

my $ldap = new Net::LDAP( "directory.int.censhare.com",
	version => 3,
	scheme => 'ldaps',
        ) or die "$@";
$ldap->bind( dn => $ldapUser, password => $ldapPass ) or die "$@";

sub usage {
  print STDERR "\nusage: $0 <uid> [hostname] [light]\n";
  print STDERR " - Lists ssh private keys of users allowed to login as 'uid' from Active Directory.\n";
  print STDERR " - Valid uids are 'root', 'corpus', 'oracle', 'git' 'postgres' or 'nagios'.\n";
  print STDERR " - Hostname is the one on which the keys will be deployed (NOT in use atm).\n";
  print STDERR " - If 'light' is given as a second argument, it lists only the keys, w/o the comment field.\n\n";
  exit 1;
}

my $search = $ldap->search (base => $ldapBase, scope => 'sub', filter => $ldapFilterUsers);
my @result = $search->entries;

for (@result) {
  my $member = decode_utf8 $_->dn;
  push (@users,$member);
}

my %seen =() ;
my @uniqueUsers = sort(grep { ! $seen{$_}++ } @users);

my $search = $ldap->search (base => $ldapBase, scope => 'sub', filter => $ldapFilterDemigods);
my @result = $search->entries;
for (@result) {
  my $demigod = decode_utf8 $_->dn;
  push (@demigods, $demigod);
  my $search = $ldap->search (base => $demigod, filter => 'objectClass=*');
  my @result = $search->entries;
  for (@result) {
    $cn = decode_utf8 $_->get_value ('cn');
    $sAMAccountName = $_->get_value ('sAMAccountName');
    $mail = $_->get_value ('mail');
    $keys = $_->get_value ('sshPublicKey', asref => 1);
    foreach $key (@$keys) {
      if ("$ARGV[1]" ne "light") {
        my $file = $keyPath . "/demigods/" . $sAMAccountName . ".pub";
        open (my $KEYFILE, ">:encoding(UTF-8)", $file) or die "CANNOT OPEN FILE $file $!";
        printf $KEYFILE "$key";
        printf $KEYFILE " $cn ($mail)\n";
        close $KEYFILE;
      }
    }
  }
}

for $user (@uniqueUsers) {
  my $search = $ldap->search (base => $user, filter => 'objectClass=*');
  my @result = $search->entries;
  for (@result) {
    next if (grep (/^$user$/, @demigods) && $arg eq "root");
    $cn = decode_utf8 $_->get_value ('cn');
    $sAMAccountName = $_->get_value ('sAMAccountName');
    $mail = $_->get_value ('mail');
    $keys = $_->get_value ('sshPublicKey', asref => 1);
    foreach $key (@$keys) {
      if ("$ARGV[1]" ne "light") {
        my $file = $keyPath ."/" . "$arg/" . $sAMAccountName . ".pub";
        open (my $KEYFILE, ">:encoding(UTF-8)", $file) or die "CANNOT OPEN FILE $file $!";
        printf $KEYFILE "$key";
        printf $KEYFILE " $cn ($mail)\n";
        close $KEYFILE;
      }
    }
  }
}

$ldap->unbind;
