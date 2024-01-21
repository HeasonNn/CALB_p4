/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
*************************************************************************/

#define MAX_PROFILE_MEMBERS 2048
#define MAX_GROUP_SIZE 120
#define MAX_GROUPS 1024 

/* The number of required hash bits depends on both the selection algorithm 
 * (resilient or fair) and the maximum group size
 *
 * The rules are as follows:
 *
 * if MAX_GROUP_SZIE <= 120:      subgroup_select_bits = 0
 * elif MAX_GROUP_SIZE <= 3840:   subgroup_select_bits = 10
 * elif MAX_GROUP_SIZE <= 119040: subgroup_select_bits = 15
 * else: ERROR
 *
 * The rules for the hash size are:
 *
 * FAIR:      14 + subgroup_select_bits
 * RESILIENT: 51 + subgroup_select_bits
 *
 */
#if RESILIENT_SELECTION == 0
  const SelectorMode_t SELECTION_MODE = SelectorMode_t.FAIR;
  #define BASE_HASH_WIDTH 14
#else
  const SelectorMode_t SELECTION_MODE = SelectorMode_t.RESILIENT;
  #define BASE_HASH_WIDTH 51
#endif /* RESILIENT_SELECTION */

#if MAX_GROUP_SIZE <= 120
  #define SUBGROUP_BITS 0
#elif MAX_GROUP_SIZE <= 3840
  #define SUBGROUP_BITS 10
#elif MAX_GROUP_SIZE <= 119040
  #define SUBGROUP_BITS 15
#else
  #error "Maximum Group Size cannot exceed 119040 members on Tofino"
#endif /* MAX_GROUP_SIZE */

/*
 * HASH_WIDTH final definition
 */
#define HASH_WIDTH (BASE_HASH_WIDTH + SUBGROUP_BITS)

#define REG_IDX_WIDTH 9
#define REG_IDX_SIZE 1 << REG_IDX_WIDTH
typedef bit<REG_IDX_WIDTH> port_reg_idx_width_t;

/* 
 * Since we will be calculating hash in 32-bit pieces, we will have this 
 * definition, which will be either bit<32>, bit<64> or bit<96> depending
 * on HASH_WIDTH
 */
typedef bit<(((HASH_WIDTH + 32)/32)*32)> selector_hash_t;

const bit<32> ECMP_SIZE = 16384;

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_FEEDBACK = 0x7777;

const int NEXTHOP_ID_WIDTH = 14;
typedef bit<(NEXTHOP_ID_WIDTH)> nexthop_id_t;

typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_TYPE_I2E  = 1;
const mirror_type_t MIRROR_TYPE_E2E  = 2;

const bit<3> FEEDBACK_DIGEST = 1;
const bit<3> RTT_DIGEST      = 2;

// egress mirror for feedback
typedef bit<2> pkt_type_t;
const pkt_type_t PKT_TYPE_NORMAL     = 1;
const pkt_type_t PKT_TYPE_MIRROR     = 2;
const pkt_type_t PKT_TYPE_RTT_MIRROR = 3;

// define device type
typedef bit<3> device_type_t;
const device_type_t DEVICE_TYPE_SRC  = 1;
const device_type_t DEVICE_TYPE_DST  = 2;

const bit<2> RTT_OPT_ECHO     = 1;
const bit<2> RTT_OPT_REPLY    = 2;
const bit<2> RTT_OPT_REDIRECT = 3;

const int IPV4_HOST_TABLE_SIZE = 131072;
const int IPV4_LPM_TABLE_SIZE  = 12288;
const int NEXTHOP_TABLE_SIZE   = 1 << NEXTHOP_ID_WIDTH;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

header ethernet_h {
    bit<48>     dst_addr;
    bit<48>     src_addr;
    bit<16>     ether_type;
}

header ipv4_h {
    bit<4>      version;
    bit<4>      ihl;
    bit<6>      dscp;
    bit<2>      ecn;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdr_checksum;
    bit<32>     src_addr;
    bit<32>     dst_addr;
}

header tcp_h {
    bit<16>     srcPort;
    bit<16>     dstPort;
    bit<32>     seqNo;
    bit<32>     ackNo;
    bit<4>      dataOffset;
    bit<4>      res;
    bit<1>      cwr;
    bit<1>      ece;
    bit<1>      urg;
    bit<1>      ack;
    bit<1>      psh;
    bit<1>      rst;
    bit<1>      syn;
    bit<1>      fin;
    bit<16>     window;
    bit<16>     checksum;
    bit<16>     urgentPtr;
}

header mirror_h {
    pkt_type_t  pkt_type;
    PortId_t    egress_port;
    QueueId_t   qid;
    bit<6>      pad0;   MirrorId_t  mirror_session;
    bit<4>      pad1;
    bit<2>      enq_congest_stat;
    bit<2>      deq_congest_stat;
    bit<8>      app_pool_congest_stat;

    bit<16>     enq_qdepth;
    bit<16>     deq_qdepth;
    bit<16>     enq_tstamp;
}

header rtt_mirror_h {
    pkt_type_t  pkt_type;
    bit<4>      pad0;
    MirrorId_t  mirror_session;
}

header feedback_h {
    bit<2>      pad0;
    PortId_t    egress_port;
    QueueId_t   qid;

    bit<4>      pad1;
    bit<2>      enq_congest_stat;
    bit<2>      deq_congest_stat;
    bit<8>      app_pool_congest_stat;

    bit<16>     enq_qdepth;
    bit<16>     deq_qdepth;
    bit<16>     enq_tstamp;
}

header rtt_probe_h {
    bit<4>      pad0;
    bit<2>      rtt_type;
    bit<2>      rtt_opt;
}

struct headers_t {
    ethernet_h  ethernet;
    feedback_h  feedback;
    ipv4_h      ipv4;
    tcp_h       tcp;
    rtt_probe_h rtt_probe;
}

struct my_ingress_metadata_t {
    bit<1>      ipv4_csum_err;
    PortId_t    ingress_port;
    PortId_t    egress_port;
    feedback_h  feedback;
    bit<3>      device_type;
    bit<10>     hash_10;

    // rtt filed
    pkt_type_t  pkt_type;
    bit<32>     rtt_val;
    bit<32>     rtt_timestamp0;
    bit<32>     rtt_timestamp1;
    MirrorId_t  rtt_mirror_session;
    bit<1>      bypass;

    // debug filed
    bit<16>     reg_val;
    bit<1>      reg_result;
    
    bit<16>     debug_val1;
    bit<16>     debug_val2;
}

struct my_egress_metadata_t {
    pkt_type_t  pkt_type;

    // mirror_h
    mirror_h    mirror_md;

    // rtt_mirror_h
    rtt_mirror_h rtt_mirror_md;
}

struct feedback_digest_t {
    bit<3>      digest_type;

    bit<16>     enq_qdepth;
    bit<16>     deq_qdepth;
    bit<16>     enq_tstamp;

    PortId_t    egress_port;
    QueueId_t   qid;

    bit<2>      enq_congest_stat;
    bit<2>      deq_congest_stat;
    bit<8>      app_pool_congest_stat;
}

struct rtt_digest_t {
    bit<16>     debug_val1;
    
    bit<3>      digest_type;
    bit<10>     flow_hash;
    bit<32>     rtt_val;

    //debug filed
    bit<16>     debug_val2;
}

struct port_reg_t {
    bit<32>     timestamp;
    bit<32>     congest_stat;
}
