#!/usr/bin/env perl

# Project website:: http://snoffer.tad0.org
# Licence:: CC-NC-BY-SA

# UDP sniffer for snoffer
# v0.5.1 - 01/07/2016 - some code cleaning and comments
# v0.5 - 21/08/2012 - choose interface
# v0.4 - 24/04/2012 - tAd tad0.org

use strict;
use warnings;
use Getopt::Std;
use diagnostics;
use Net::PcapUtils;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::UDP;
use IO::Socket::INET;

my $i=1;
my $data;
my $freq;

## Usage
sub Usage
{
    my $prog = $0;
    $prog =~ s/.*\///g;

print STDERR <<EOM;
Usage: $prog -i interface
    -i: listening interface
    -h: this help
EOM
    exit(1) ;
}

## Arguments
my $args = {};
getopts('i:h', $args);

if (exists($args->{'h'})
    || (not exists($args->{'i'})))
{
    Usage();
}

my $interface = $args->{'i'};

# Filtering, Device, ...
Net::PcapUtils::loop(\&process_pkt, FILTER => 'udp', DEV => $interface, PROMISC => 1,);

sub process_pkt {
  my ($user_data,$hdr,$pkt)=@_;
  my $eth=NetPacket::Ethernet->decode($pkt);
  if($eth->{type} == 2048){
    my $ip=NetPacket::IP->decode($eth->{data});
    if($ip->{proto} == 17){
      my $udp=NetPacket::UDP->decode($ip->{data});
	if($udp->{dest_port} < 1024){
	# Print data informations into terminal
	print "[UDP] $ip->{src_ip}($udp->{src_port}) -> $ip->{dest_ip}($udp->{dest_port}) - ";
	$i++;
	$freq=(227.5+($udp->{dest_port})*0.0634);

	# Open a socket to PureData
	my $Socket=new IO::Socket::INET->new(
	PeerPort=>4442,
	Proto=>'tcp',
	PeerAddr=>'127.0.0.1',
	LocalAddr => '127.0.0.1',
	) or die "Can't bind : $@\n Is PureData running? ... \n";

	# Send data to PureData
	print "$freq Hz \n";
	print $Socket $freq;
	print $Socket ';';
	close($Socket);
      }
    }
  }
}


