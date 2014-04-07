#!/usr/bin/perl -w

# TCP sniffer for Sn0ffer
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
#Net::PcapUtils::loop(\&process_pkt, FILTER => 'not port 4444 and not port 4443 and not port 4442', DEV => $interface, PROMISC => 1,);
#Net::PcapUtils::loop(\&process_pkt, FILTER => '', DEV => $interface, PROMISC => 1,);
Net::PcapUtils::loop(\&process_pkt, FILTER => '', DEV => $interface, PROMISC => 1,);

## Socket1
#my $Socket1=new IO::Socket::INET->new(
# PeerPort=>4444,
# Proto=>'tcp',
# PeerAddr=>'127.0.0.1',
# LocalAddr => '127.0.0.1',
#) or die "Can't bind : $@\n";

## Socket2
#my $Socket2=new IO::Socket::INET->new(        
# PeerPort=>4454,
# Proto=>'tcp',
# PeerAddr=>'127.0.0.1',
# LocalAddr => '127.0.0.1',
#) or die "Can't bind : $@\n";


sub process_pkt {
  my ($user_data,$hdr,$pkt)=@_;
  my $eth=NetPacket::Ethernet->decode($pkt);
  if($eth->{type} == 2048){
    my $ip=NetPacket::IP->decode($eth->{data});
    if($ip->{proto} == 6){
      my $tcp=NetPacket::TCP->decode($ip->{data});
if ($tcp->{dest_port}<10000){
	print "[TCP] $ip->{src_ip}($tcp->{src_port}) -> $ip->{dest_ip}($tcp->{dest_port}) - ";
      	#print "$i - $ip->{src_ip}($tcp->{src_port}) -> $ip->{dest_ip}($tcp->{dest_port}) - ";
	$i++;
                #$freq=(227.5+($tcp->{dest_port})*0.0634);
		#$freq=(($tcp->{dest_port})*4.1585);	
		$freq=$tcp->{dest_port};

	my $Socket=new IO::Socket::INET->new(
        PeerPort=>4444,
        Proto=>'tcp',
	PeerAddr=>'127.0.0.1',
	LocalAddr => '127.0.0.1',
        ) or die "Can't bind : $@\n";
	
	print "$freq Hz \n";
	print $Socket $freq;
	print $Socket ';';
	close($Socket);
      }

if ($tcp->{src_port}<1024){
        print "[TCP] $ip->{dest_ip}($tcp->{dest_port}) <- $ip->{src_ip}($tcp->{src_port}) - ";
        #print "$i - $ip->{src_ip}($tcp->{src_port}) -> $ip->{dest_ip}($tcp->{dest_port}) - ";
        $i++;
                #$freq=(227.5+($tcp->{dest_port})*0.0634);
                #$freq=(($tcp->{dest_port})*4.1585);
		$freq=($tcp->{src_port});

        my $Socket=new IO::Socket::INET->new(
        PeerPort=>4444,
        Proto=>'tcp',
        PeerAddr=>'127.0.0.1',
        LocalAddr => '127.0.0.1',
        ) or die "Can't bind : $@\n";

        print "$freq Hz \n";
        print $Socket $freq;
        print $Socket ';';
	close($Socket)
      }

if ($tcp->{src_port}>1024){
	print "[TCP] $ip->{dest_ip}($tcp->{dest_port}) <- $ip->{src_ip}($tcp->{src_port}) - ";
        #print "$i - $ip->{src_ip}($tcp->{src_port}) -> $ip->{dest_ip}($tcp->{dest_port}) - ";
        $i++;
                #$freq=(227.5+($tcp->{dest_port})*0.0634);
                #$freq=(($tcp->{dest_port})*4.1585);
                #########$freq=(1024+(($tcp->{src_port})/(65535-1024)));
		$freq=($tcp->{src_port});

        my $Socket=new IO::Socket::INET->new(
        PeerPort=>4454,
        Proto=>'tcp',
        PeerAddr=>'127.0.0.1',
        LocalAddr => '127.0.0.1',
        ) or die "Can't bind : $@\n";

        print "$freq Hz \n";
        print $Socket $freq;
        print $Socket ';';
	close($Socket)
      }


    }
  }
}


