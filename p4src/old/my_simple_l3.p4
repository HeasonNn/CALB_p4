/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
*************************************************************************/
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_FEEDBACK = 0x7777;

const int NEXTHOP_ID_WIDTH = 14;
typedef bit<(NEXTHOP_ID_WIDTH)> nexthop_id_t;

typedef bit<3> mirror_type_t;
typedef bit<8> pkt_type_t;

const mirror_type_t MIRROR_TYPE_I2E = 1;
const mirror_type_t MIRROR_TYPE_E2E = 2;
const pkt_type_t PKT_TYPE_NORMAL = 1;
const pkt_type_t PKT_TYPE_MIRROR = 2;

/* Table Sizing */
const int IPV4_HOST_TABLE_SIZE = 131072;
const int IPV4_LPM_TABLE_SIZE  = 12288;
const int NEXTHOP_TABLE_SIZE   = 1 << NEXTHOP_ID_WIDTH;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/
/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    bit<48>  dst_addr;
    bit<48>  src_addr;
    bit<16>  ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<6>   dscp;
    bit<2>   ecn;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header tcp_h {
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

header mirror_h {
    pkt_type_t  pkt_type;

    bit<7> pad0;  PortId_t  egress_port;
    bit<6> pad1;  MirrorId_t  mirror_session;

    bit<16> enq_qdepth;
    bit<16> deq_qdepth;
    bit<16> enq_tstamp;
}

header feedback_h {
    bit<7> pad0;  PortId_t  egress_port;
    
    bit<16> enq_qdepth;
    bit<16> deq_qdepth;
    bit<16> enq_tstamp;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h  ethernet;
    feedback_h  feedback;
    ipv4_h      ipv4;
    tcp_h       tcp;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bit<1> ipv4_csum_err;
    PortId_t  ingress_port;

    feedback_h feedback;
}

    /***********************  P A R S E R  **************************/

parser IngressParser(packet_in        pkt,
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    Checksum() ipv4_checksum;
    
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    state meta_init {
        meta.ipv4_csum_err = 0;
        meta.ingress_port = ig_intr_md.ingress_port;
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:     parse_ipv4;
            ETHERTYPE_FEEDBACK: parse_feedback;
            default:            accept;
        }
    }
    
    state parse_feedback {
        pkt.extract(hdr.feedback);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        ipv4_checksum.add(hdr.ipv4);
        meta.ipv4_csum_err = (bit<1>)ipv4_checksum.verify();
        transition parse_tcp;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{   
    nexthop_id_t    nexthop_id = 0;
    bit<8>          ttl_dec = 0;

    action set_nexthop(nexthop_id_t nexthop) {
        nexthop_id = nexthop;
    }
    
    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action l3_switch(PortId_t port, bit<48> new_mac_da, bit<48> new_mac_sa) {
        hdr.ethernet.dst_addr = new_mac_da;
        hdr.ethernet.src_addr = new_mac_sa;
        hdr.ipv4.ttl =  hdr.ipv4.ttl - 1;
        send(port); 
    }

    action update_digest() {
        ig_dprsr_md.digest_type = 1;
    }

    table ipv4_host {
        key = { hdr.ipv4.dst_addr : exact; }
        actions = {
            set_nexthop;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = IPV4_HOST_TABLE_SIZE;
    }

    table ipv4_lpm {
        key     = { hdr.ipv4.dst_addr : lpm; }
        actions = { set_nexthop; }
        
        default_action = set_nexthop(0);
        size = IPV4_LPM_TABLE_SIZE;
    }

    table nexthop {
        key = { nexthop_id : exact; }
        actions = { send; drop; l3_switch; }
        size = NEXTHOP_TABLE_SIZE;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            if (meta.ipv4_csum_err == 0 && hdr.ipv4.ttl > 1) {
                if (!ipv4_host.apply().hit) {
                    ipv4_lpm.apply();
                }
            }
        }
        
        nexthop.apply();

        if(meta.ingress_port == (PortId_t)68) {
            update_digest();
            drop();
        }
    }
}

    /*********************  D E P A R S E R  ************************/

struct digest_t {
    bit<16> enq_qdepth;
    bit<16> deq_qdepth;
    bit<16> enq_tstamp;
    PortId_t  egress_port;
}

control IngressDeparser(packet_out pkt,
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Checksum() ipv4_checksum;
    
    Digest <digest_t>() my_digest;

    apply {
        if (ig_dprsr_md.digest_type == 1) {
            my_digest.pack({
                hdr.feedback.enq_qdepth,
                hdr.feedback.deq_qdepth,
                hdr.feedback.enq_tstamp,
                hdr.feedback.egress_port
            });
        }

        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.dscp,
            hdr.ipv4.ecn,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr
        });

        // pkt.emit(hdr);

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.feedback);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
    ethernet_h  ethernet;
    feedback_h  feedback;
    ipv4_h      ipv4;
    tcp_h       tcp;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
    mirror_h mirror_md;
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        transition parser_metadata;
    }

    state parser_metadata {
        mirror_h  mirror_hdr = pkt.lookahead<mirror_h>();
        transition select(mirror_hdr.pkt_type) {
            PKT_TYPE_MIRROR: parse_mirror_md;
            default: parse_normal_md;
        }
    }
    
    state parse_mirror_md {
        pkt.extract(meta.mirror_md);
        transition parse_ethernet;
    }

    state parse_normal_md {
        meta.mirror_md = { PKT_TYPE_NORMAL, 0, 0, 0, 0, 0, 0, 0 };
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:     parse_ipv4;
            // ETHERTYPE_FEEDBACK: parse_feedback;
            default:            accept;
        }
    }
    
    // state parse_feedback {
    //     pkt.extract(hdr.feedback);
    //     transition parse_ipv4;
    // }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition parse_tcp;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    action set_mirror_action() {
        // TODO: using eg_intr_md data emplace test data
        eg_dprsr_md.mirror_type = MIRROR_TYPE_E2E;

        meta.mirror_md.pkt_type = PKT_TYPE_MIRROR;
        meta.mirror_md.egress_port = 100;
        meta.mirror_md.mirror_session = (MirrorId_t)1;

        meta.mirror_md.enq_qdepth = 2;
        meta.mirror_md.deq_qdepth = 3;
        meta.mirror_md.enq_tstamp = 4;
    }
    
    apply {
        if(meta.mirror_md.pkt_type == PKT_TYPE_NORMAL){
            set_mirror_action();
        } else if(meta.mirror_md.pkt_type == PKT_TYPE_MIRROR) {
            hdr.feedback.setValid();
            hdr.ethernet.ether_type = ETHERTYPE_FEEDBACK;

            hdr.feedback.pad0 = 0;
            hdr.feedback.egress_port = meta.mirror_md.egress_port;
            hdr.feedback.enq_qdepth = meta.mirror_md.enq_qdepth;
            hdr.feedback.deq_qdepth = meta.mirror_md.deq_qdepth;
            hdr.feedback.enq_tstamp = meta.mirror_md.enq_tstamp;
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    Mirror() mirror;

    apply {
        if(eg_dprsr_md.mirror_type == MIRROR_TYPE_E2E) {
            mirror.emit<mirror_h>(
                meta.mirror_md.mirror_session, 
                {   
                    // meta.mirror_md

                    meta.mirror_md.pkt_type,
                    meta.mirror_md.pad0, meta.mirror_md.egress_port,
                    meta.mirror_md.pad1, meta.mirror_md.mirror_session,
                    meta.mirror_md.enq_qdepth, 
                    meta.mirror_md.deq_qdepth, 
                    meta.mirror_md.enq_tstamp
            });
        }
        // pkt.emit(hdr);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.feedback);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;