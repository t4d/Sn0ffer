#!/usr/bin/env perl

# Project website:: http://snoffer.tad0.org
# Licence:: CC-NC-BY-SA

# TCP sniffer for Sn0ffer
# v0.5.1 - 01/07/2016 - some code cleaning and comments
# v0.5 - 04/07/2013 - new
# v0.4 - 05/05/2010 - tAd tad0.org

use strict;
use warnings;
use Getopt::Std;
use Net::PcapUtils;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
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
# You can use a Pcap style filtering rule
# Net::PcapUtils::loop(\&process_pkt, FILTER => 'not port 4444 and not port 4443 and not port 4442', DEV => $interface, PROMISC => 1,);
Net::PcapUtils::loop(\&process_pkt, FILTER => '', DEV => $interface, PROMISC => 1,);



sub process_pkt {
  my ($user_data,$hdr,$pkt)=@_;
  my $eth=NetPacket::Ethernet->decode($pkt);
  if($eth->{type} == 2048){
    my $ip=NetPacket::IP->decode($eth->{data});
    if($ip->{proto} == 6){
      my $tcp=NetPacket::TCP->decode($ip->{data});
      
if ($tcp->{dest_port}<10000){
		# Print data informations into terminal
		print "[TCP] $ip->{src_ip}($tcp->{src_port}) -> $ip->{dest_ip}($tcp->{dest_port}) - ";
		$i++;
		$freq=$tcp->{dest_port};
	
		# Open a socket to PureData
		my $Socket=new IO::Socket::INET->new(
		PeerPort=>4444,
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

if ($tcp->{src_port}<1024){
		# Print data informations into terminal
        print "[TCP] $ip->{dest_ip}($tcp->{dest_port}) <- $ip->{src_ip}($tcp->{src_port}) - ";
        $i++;
		$freq=($tcp->{src_port});

		# Open a socket to PureData
        my $Socket=new IO::Socket::INET->new(
        PeerPort=>4444,
        Proto=>'tcp',
        PeerAddr=>'127.0.0.1',
        LocalAddr => '127.0.0.1',
		) or die "Can't bind : $@\n Is PureData running? ... \n";

		# Send data to PureData
        print "$freq Hz \n";
        print $Socket $freq;
        print $Socket ';';
		close($Socket)
      }

if ($tcp->{src_port}>1024){
		# Print data informations into terminal
		print "[TCP] $ip->{dest_ip}($tcp->{dest_port}) <- $ip->{src_ip}($tcp->{src_port}) - ";
        $i++;
		$freq=($tcp->{src_port});
		
		# Open a socket to PureData
        my $Socket=new IO::Socket::INET->new(
        PeerPort=>4454,
        Proto=>'tcp',
        PeerAddr=>'127.0.0.1',
        LocalAddr => '127.0.0.1',
		) or die "Can't bind : $@\n Is PureData running? ... \n";
		
		# Send data to PureData
        print "$freq Hz \n";
        print $Socket $freq;
        print $Socket ';';
		close($Socket)
      }
    }
  }
}


