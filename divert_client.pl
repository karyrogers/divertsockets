#!/usr/bin/perl

# For macports perl location
use lib '/opt/local/lib/perl5/site_perl/5.16.3';

use Net::Divert;
use NetPacket::IP qw(IP_PROTO_TCP);
use NetPacket::TCP qw(SYN RST ACK);
use strict;

my $divobj = Net::Divert->new('localhost',45678);
$divobj->getPackets(\&processPkt);

sub processPkt {
    my ($packet, $fwtag) = @_;

    # decode the IP header
    my $ip_obj = NetPacket::IP->decode($packet);

    # check if this is a TCP packet
    if($ip_obj->{proto} == IP_PROTO_TCP) {

        # decode the TCP header
        my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});

	# HACK ALERT:
	# Check for SYN flag and set RST/ACK
	if ($tcp_obj->{flags} == SYN) {
	    print "SYN -> RST/ACK\n";
            $tcp_obj->{flags} = RST | ACK;
	}

        # construct the new ip packet
        $ip_obj->{data} = $tcp_obj->encode($ip_obj);
        $packet = $ip_obj->encode;

    }

    # write it back out
    $divobj->putPacket($packet,$fwtag);
}
