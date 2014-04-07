#!/usr/bin/perl -w

# Layer2 sniffer for snoffer
# 0.5 - 21/08/2012 - choosing interface
# 0.4.1 - 23/03/2012 - changing default 444Hz for 115Hz 
# 0.4 - 29/02/2012 - adding the name of protocol seen
# 0.3 - 20/02/2012 - tAd tad0.org

use strict;
use warnings;
use Getopt::Std;
use integer;
use diagnostics;
use Net::PcapUtils;
use NetPacket::Ethernet;
use IO::Socket::INET;

 my $freq;
 my $proto;

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

  sub process_pkt {
      my($arg, $hdr, $pkt) = @_;

	      my $eth_obj = NetPacket::Ethernet->decode($pkt);
  	if ($eth_obj->{type} != '2048') {   			#not IPv4 
		#print("$eth_obj->{src_mac}:$eth_obj->{dest_mac} $eth_obj->{type} $eth_obj->{data}\n");
		#printf("%12X:",$eth_obj->{src_mac});
		#printf("%12X\t",$eth_obj->{dest_mac});
		print("$eth_obj->{src_mac}:$eth_obj->{dest_mac}\t");
		printf("%04X\t",$eth_obj->{type});
		#printf("%12X:%12X %04X %04X\n",$eth_obj->{src_mac},$eth_obj->{dest_mac},$eth_obj->{type},$eth_obj->{data});

		# ou tableau freq en fct du type?
		#$freq=(227.5+($eth_obj->{type})*0.0317);
		# a transformer en hexa
		if ($eth_obj->{type}=='34525') {$freq='55'; $proto='IPv6';}		#86DD (IPV6)
		elsif ($eth_obj->{type}=='36864') {$freq='65';}		#
		elsif ($eth_obj->{type}=='2054') {$freq='75'; $proto='ARP';}		#0806 (ARP)
		elsif ($eth_obj->{type}=='39') {$freq='85'; $proto='STP';}		#0027 (STP)
		elsif ($eth_obj->{type}=='38') {$freq='95'; $proto='STP?';}            #0026 (STP?)
		elsif ($eth_obj->{type}=='33079') {$freq='105'; $proto='IPX/SPX';}            #8137 (IPX/SPX)
	
		elsif ($eth_obj->{type}=='34958') {$freq='115'; $proto='EAPoL';}		#888E (EAP over Lan)
		else {$freq='150'; $proto='???';}
		#$freq=$eth_obj->{type};	

	my $Socket=new IO::Socket::INET->new(
        PeerPort=>'4443',
        Proto=>'tcp',
        PeerAddr=>'127.0.0.1',
        LocalAddr => '127.0.0.1',
	) or die "Can't bind : $@\n";

        print "$freq Hz - $proto\n";
        print $Socket $freq;
        print $Socket ';';

	}
  
  }

  Net::PcapUtils::loop(\&process_pkt, DEV=> $interface,);
