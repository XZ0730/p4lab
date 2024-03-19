/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP  = 0x0806;
//定义ARP涉及的字段常量
const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
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

//构造ARP报文头
header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8> hlen;
    bit<8> plen;
    bit<16> oper;
    macAddr_t srcMACAddr;
    ip4Addr_t srcIPAddr;
    macAddr_t dstMACAddr;
    ip4Addr_t dstIPAddr;
    }

//取出ip地址进行匹配，看是否需要进行ARP回复
struct metadata {
    ip4Addr_t  dst_ipv4;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    arp_t        arp;//增加ARP报文头
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
       transition par_ether;
    }

    state par_ether{
        packet.extract(hdr.ethernet);//解析以太网报头
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4:par_ipv4;//如果是IPV4报文则需解析ipv4报头
            TYPE_ARP : parse_arp;//如果是ARP报文则需解析arp报头
            default:accept;//否则直接接受
        }
    }

    state par_ipv4{
        packet.extract(hdr.ipv4);//解析ipv4报头
        transition accept;//接受
    }

    //arp解析
    state parse_arp {
        packet.extract(hdr.arp);
        //将报文中的目的IP存储到元数据中
        meta.dst_ipv4 = hdr.arp.dstIPAddr;
        transition accept;
        }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(egressSpec_t port, macAddr_t dstAddr) {
        standard_metadata.egress_spec = port;//选择目的转发端口
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;//在此交换机转发，把原先目的地址改为源地址
        hdr.ethernet.dstAddr = dstAddr;//设置控制平面下发的目的地址
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;//ttl减1
    }

    table ipv4_lpm {
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

    action send_arp_reply(macAddr_t macAddr, ip4Addr_t IPAddr) {
        hdr.ethernet.dstAddr = hdr.arp.srcMACAddr; //目的地址改为源地址
        hdr.ethernet.srcAddr = macAddr;//源地址改为当前的mac地址
         //ARP回应报文
         hdr.arp.oper = ARP_OPER_REPLY;
         //ARP回应报文具体内容
         hdr.arp.dstMACAddr = hdr.arp.srcMACAddr;
         hdr.arp.dstIPAddr = hdr.arp.srcIPAddr;
         hdr.arp.srcMACAddr = macAddr;
         hdr.arp.srcIPAddr = IPAddr;
        //从入端口转发出去
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        }

    table arp_ternary {
        key = {
            hdr.arp.oper : exact;
            hdr.arp.dstIPAddr : lpm;
            }
        actions = {
            send_arp_reply;
            drop;
            }
        const default_action = drop();
    }

    apply {
        // 如果IPv4类型存在则进行IPv4转发
        if(hdr.ethernet.etherType == TYPE_IPV4) {
            ipv4_lpm.apply();
        }
        // 响应ARP匹配
        else if(hdr.ethernet.etherType == TYPE_ARP) {
            arp_ternary.apply();
        }
    }

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
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


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // 重组数据包头
        packet.emit(hdr.ethernet);
        // 重组ARP数据包头
        packet.emit(hdr.arp);
        //重组IP数据包头
        packet.emit(hdr.ipv4);
        //注意顺序
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;