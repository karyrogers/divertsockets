#!/usr/bin/perl

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
	# check for RST/ACK flags and change to SYN
	if ($tcp_obj->{flags} == (RST | ACK)) {
	    print "RST/ACK -> SYN\n";
	    $tcp_obj->{flags} = SYN;
	}

        # construct the new ip packet
        $ip_obj->{data} = $tcp_obj->encode($ip_obj);
        $packet = $ip_obj->encode;

    }

    # write it back out
    $divobj->putPacket($packet,$fwtag);
}
