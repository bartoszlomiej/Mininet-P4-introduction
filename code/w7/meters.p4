#include <core.p4>

#include <v1model.p4>

//#include <psa-for-bmv2.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP = 6;
const bit<8> TYPE_UDP = 17;
/*
match_kind {
    exact
}

#define PORT_4 4;
#define PORT_8 8;
*/
//typedef bit<9>   port_num_t;
typedef bit<9> egressSpec_t;
typedef bit<48>  macAddr_t;
typedef bit<32>  ip4Addr_t;
typedef bit<128> ip6Addr_t;
typedef bit<2> color_t;

header ethernet_t{
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t{
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

//one header for both tcp & udp -> only port does matter
header udp_t{
    bit<16> source_port;
    bit<16> destination_port;
    bit<16> length;
    bit<16> check_sum;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct headers{
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
}

struct metadata{
    bit<16> port;
    color_t pkt_color;
}

parser parserI(packet_in pkt, out headers hdr, inout metadata meta, inout standard_metadata_t stdmeta){
    state start{
	//	pkt.extraction(hdr.h1);
	transition parse_ethernet;
    }

    state parse_ethernet {
	pkt.extract(hdr.ethernet);
	transition select(hdr.ethernet.etherType){
	    TYPE_IPV4: parse_ipv4;
	    default: accept;
	}
    }

    state parse_ipv4{
	pkt.extract(hdr.ipv4);
	transition select(hdr.ipv4.protocol){
	    TYPE_TCP: parse_transport;
	    TYPE_UDP: parse_transport;
	    default: accept;
	}
    }

    state parse_transport{
	pkt.extract(hdr.tcp);
	transition accept;
    }
}

control myVerifyChecksum(inout headers hdr, inout metadata meta){
    apply{}
}

control cIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t stdmeta){
    
    direct_meter<color_t>(MeterType.bytes) dmeter_instance;
    action drop(){
	mark_to_drop(stdmeta);
    }

    action mark_packet(){
	dmeter_instance.read(meta.pkt_color);
    }
    
    table mark_packet_any{
	key = {
	    hdr.ipv4.dstAddr: lpm;	    
	}
	actions = {
	    mark_packet;
	    drop;
	}
	meters = dmeter_instance;
	default_action = mark_packet; 
    }

    table filter_meters_exact{
	key = {
	    meta.pkt_color: exact;
	}
	actions = {
	    NoAction;
	    drop;
	}
	default_action = drop();
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port){
	stdmeta.egress_spec = port;
	hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
	hdr.ethernet.dstAddr = dstAddr;
	hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm{
	key = {
	    hdr.ipv4.dstAddr: lpm;
	}
	actions = {
	    ipv4_forward;
	    drop;
	    NoAction;
	}
	size = 1024;
	default_action = NoAction();
    }

    table traffic_filter{
	key = {
	    hdr.ipv4.dstAddr: ternary;
	    //	    hdr.tcp.dstPort: ternary;
	    //	    hdr.ipv4.protocol: exact;
	}
	actions = {
	    ipv4_forward;
	    drop;
	}
	default_action = drop();
    }

    apply{
	if(hdr.ipv4.isValid()){
	    ipv4_lpm.apply();
	    mark_packet_any.apply();
	    filter_meters_exact.apply();

	    /*
	    if(hdr.tcp.isValid()){
		traffic_filter.apply();
	    }
	    */
	}
    }
}


control cEgress(inout headers hr,  inout metadata meta, inout standard_metadata_t stdmeta){
    apply{
	}
}


control myComputeChecksum(inout headers hdr, inout metadata meta){
     apply{
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }    
}

control deparserI(packet_out packet, in headers hdr){
    apply{
	packet.emit(hdr.ethernet);
	packet.emit(hdr.ipv4);
	packet.emit(hdr.tcp);
    }
}

V1Switch(
    parserI(), 
    myVerifyChecksum(),
    cIngress(),
    cEgress(),
    myComputeChecksum(),
    deparserI()
) main;