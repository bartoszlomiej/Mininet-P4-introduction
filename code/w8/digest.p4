#include <core.p4>

#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_8021Q = 0x8100;
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

typedef bit<16> tpid_t;

header ethernet_t{
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header vlanTag_t{
    tpid_t tpid; //Tag protocol identifier
    bit<1> pcp; //Priority code point 
    bit<3> dei; //Drop eligible indicator
    bit<12> vid; //VLAN identifier
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

struct headers{
    ethernet_t ethernet;
    vlanTag_t vlanTag;
    ipv4_t ipv4;
}

struct mac_learn_t{
    bit<48> srcAddr;
    bit<9> ingress_port;
    bit<32> srcIpAddr;
}

struct metadata{
    egressSpec_t port;
    mac_learn_t mac_learn_msg;
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
	meta.mac_learn_msg.srcIpAddr = hdr.ipv4.srcAddr;
	transition accept;
    }
}

control myVerifyChecksum(inout headers hdr, inout metadata meta){
    apply{}
}

control cIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t stdmeta){

    action drop(){
	mark_to_drop(stdmeta);
    }

    action unknown_source(){
	meta.mac_learn_msg.srcAddr = hdr.ethernet.srcAddr;
	meta.mac_learn_msg.ingress_port = stdmeta.ingress_port;
	//	meta.mac_learn_msg.srcIpAddr = hdr.ipv4.srcAddr;
	digest<mac_learn_t>(0, meta.mac_learn_msg); //possible error
    }
    
    table learned_MAC{
	key = {
	    hdr.ethernet.srcAddr: exact;
	}
	actions = {
	    unknown_source;
	    NoAction;
	}
	default_action = unknown_source();
    }

    action mac_forward(macAddr_t dstAddr, egressSpec_t port){
	stdmeta.egress_spec = port;
	//	hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
	hdr.ethernet.dstAddr = dstAddr;
    }

    table l2_table{
	key = {
	    hdr.ipv4.dstAddr: exact;
	}
	actions = {
	    mac_forward;
	    drop;
	    NoAction;
	}
	size = 1024;
	default_action = NoAction();
    }    

    apply{
	if(hdr.ipv4.isValid()){
	    learned_MAC.apply();
	    l2_table.apply();
	}
    }
}


control cEgress(inout headers hdr,  inout metadata meta, inout standard_metadata_t stdmeta){

    action remove_vlanTag(){
	hdr.vlanTag.setInvalid();
	hdr.ethernet.etherType = TYPE_IPV4;
    }

    action remove(){
	hdr.vlanTag.setInvalid();
	hdr.ethernet.etherType = TYPE_IPV4;
    }
    
    table remove_vlanTag_exact{
	key = {
	    meta.port: exact;
	}

	actions = {
	    remove_vlanTag;
	    remove;
	    NoAction;
	}
	default_action = NoAction();
    }
    apply{
	/*
	if(hdr.vlanTag.isValid()){
	    remove_vlanTag_exact.apply();
	}
	*/

    }
}


control myComputeChecksum(inout headers hdr, inout metadata meta){
    apply{/*
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
	*/
    }    
}

control deparserI(packet_out packet, in headers hdr){
    apply{
	packet.emit(hdr.ethernet);
	//	packet.emit(hdr.vlanTag);
	packet.emit(hdr.ipv4);
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