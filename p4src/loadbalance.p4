/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>

#include "include/header.p4"
#include "include/parser.p4"

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

#include "include/calc_hash.p4"

control Ingress(
    inout   headers_t                                   hdr,
    inout   my_ingress_metadata_t                       meta,
    in      ingress_intrinsic_metadata_t                ig_intr_md,
    in      ingress_intrinsic_metadata_from_parser_t    ig_prsr_md,
    inout   ingress_intrinsic_metadata_for_deparser_t   ig_dprsr_md,
    inout   ingress_intrinsic_metadata_for_tm_t         ig_tm_md)
{
#include "include/register_ingress.p4"

    nexthop_id_t    nexthop_id = 0;

#ifndef P4C_2228_FIXED
    @pa_container_size("ingress", "hash_0", 32)
#endif
    selector_hash_t  hash = 0;

    action set_nexthop(nexthop_id_t nexthop) {
        nexthop_id = nexthop;
    }
    
    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        meta.egress_port = port;
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

    action redirect_to_src (PortId_t new_ingress_port){
        bit<48> mac_addr_tmp;
        mac_addr_tmp = hdr.ethernet.src_addr;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = mac_addr_tmp;
        
        bit<32> ip_addr_tmp;
        ip_addr_tmp = hdr.ipv4.src_addr;
        hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr = ip_addr_tmp;

        // In order for rtt mirror to correctly match the ipv4 host table, 
        // we need to modify the ingress port to the corresponding port number.
        meta.ingress_port = new_ingress_port;

        hdr.rtt_probe.rtt_opt = RTT_OPT_REPLY;
    }

    table ipv4_host {
        key = {
            meta.ingress_port : exact;
            hdr.ipv4.dst_addr : exact;
        }
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

    Hash<bit<HASH_WIDTH>>(HashAlgorithm_t.IDENTITY) ecmp_hash;
    ActionProfile(size = MAX_PROFILE_MEMBERS) ecmp;

    ActionSelector(
        action_profile = ecmp,
        hash           = ecmp_hash,
        mode           = SELECTION_MODE,
        max_group_size = MAX_GROUP_SIZE,
        num_groups     = MAX_GROUPS) ecmp_sel;
        
#ifdef SCRAMBLE_ENABLE
    @selector_enable_scramble(SCRAMBLE_ENABLE)
#endif

    table nexthop {
        key = { 
            nexthop_id : exact; 
            hash       : selector;
        }
        actions = { send; drop; l3_switch; }
        size = NEXTHOP_TABLE_SIZE;
        implementation = ecmp_sel;
    }

    table opt_nexthop {
        key = { nexthop_id : exact;}
        actions = { send; }
        size = 64;
    }
    
    action update_device_type(bit<3> device_type) {
        meta.device_type = device_type;
    }

    table device_type {
        key = { 
            meta.ingress_port : exact;
            meta.egress_port  : exact;
        }
        actions = { 
            update_device_type;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }

    table init_rtt_probe {
        actions = {
            do_reset_rtt_probe_reg;
        }
        size = 1;
        const default_action = do_reset_rtt_probe_reg;
    }

    table read_rtt_reg {
        actions = {
            do_read_rtt_probe_reg;
        }
        size = 1;
        const default_action = do_read_rtt_probe_reg;
    }

    table calc_rtt {
        actions = {
            do_calc_rtt_val;
        }
        size = 1;
        const default_action = do_calc_rtt_val;
    }

    table redirect_rtt_probe {
        key = { 
            meta.ingress_port :     exact;
            hdr.ipv4.dst_addr :     exact; 
            hdr.rtt_probe.rtt_opt : exact;
        }
        actions = { 
            redirect_to_src;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 64;
    }

    table read_rtt_interval_reg {
        actions = {
            do_read_rtt_probe_reg;
        }
        size = 1;
        const default_action = do_read_rtt_probe_reg;    
    }

    apply {
        if(hdr.ipv4.isValid()) {

            // rtt probe pkt redirect
            if(hdr.rtt_probe.isValid()) {
                if(redirect_rtt_probe.apply().hit) {
                    meta.bypass = 1;
                }
            }

            // ECMP forward
            calc_ipv4_hashes.apply(hdr, hash);
            if (meta.ipv4_csum_err == 0 && hdr.ipv4.ttl > 1) {
                if (!ipv4_host.apply().hit) {
                    ipv4_lpm.apply();
                }
                nexthop.apply();
            }

            // generate feedback digest
            if(hdr.feedback.isValid()) {
                do_update_port_reg(hdr.feedback.egress_port);
                ig_dprsr_md.digest_type = FEEDBACK_DIGEST;
                meta.bypass = 1;
                drop();
            } 
            else {
                do_check_port_reg(ig_tm_md.ucast_egress_port);
                if(meta.reg_result == 1) {
                    opt_nexthop.apply();
                }
            }

            // Processing RTT probe packets in SrcToR or DstToR
            if(meta.bypass == 0) {
                if(device_type.apply().hit) {
                    meta.hash_10 = hash[9:0];

                    // SrcToR: 
                    if(meta.device_type == DEVICE_TYPE_SRC && !hdr.rtt_probe.isValid()) {
                        if(ig_intr_md.ingress_mac_tstamp[31:0] - meta.rtt_timestamp0 > 32w2000000000) {
                            init_rtt_probe.apply();
                            meta.rtt_timestamp0 = ig_intr_md.ingress_mac_tstamp[31:0];
                            hdr.rtt_probe.setValid();
                            hdr.rtt_probe.rtt_type = 1;
                            hdr.rtt_probe.pad0 = 0;
                            hdr.rtt_probe.rtt_opt = RTT_OPT_ECHO;
                        }
                    }

                    // DstToR
                    else if(meta.device_type == DEVICE_TYPE_DST && hdr.rtt_probe.isValid()) {
                        if(hdr.rtt_probe.rtt_type == 1) {
                            if(hdr.rtt_probe.rtt_opt == RTT_OPT_REPLY) {
                                bit<32> rtt_hash;
                                calc_rtt_hash.apply(hdr, rtt_hash);
                                meta.hash_10 = rtt_hash[9:0];
                                
                                read_rtt_reg.apply();
                                meta.rtt_val = ig_intr_md.ingress_mac_tstamp[31:0] - meta.rtt_timestamp0;
                                ig_dprsr_md.digest_type = RTT_DIGEST;
                                meta.debug_val1 = 1;
                                meta.debug_val2 = 2;
                                drop();
                            }
                            
                            if(hdr.rtt_probe.rtt_opt == RTT_OPT_ECHO) {
                                // rtt_probe mirror
                                ig_dprsr_md.mirror_type = MIRROR_TYPE_I2E;
                                meta.pkt_type = PKT_TYPE_RTT_MIRROR;
                                meta.rtt_mirror_session = (MirrorId_t)1;

                                hdr.rtt_probe.setInvalid();
                            }
                        }
                    }
                }
            }
        }
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control Egress(
    inout headers_t                                    hdr,
    inout my_egress_metadata_t                         meta,
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{   
    PortId_t    egress_port;
    QueueId_t   qid;
    bit<2>      enq_congest_stat;
    bit<2>      deq_congest_stat;
    bit<8>      app_pool_congest_stat;
    
    action do_feedback_mirror() {
        // TODO: using eg_intr_md data emplace test data
        eg_dprsr_md.mirror_type = MIRROR_TYPE_E2E;
        meta.mirror_md.pkt_type = PKT_TYPE_MIRROR;

        // Tofino does not support action data/constant with rotated PHV source at the same time.
        // meta.mirror_md.egress_port = eg_intr_md.egress_port;
        // meta.mirror_md.qid = eg_intr_md.egress_qid;
        // meta.mirror_md.enq_congest_stat = eg_intr_md.enq_congest_stat;
        // meta.mirror_md.deq_congest_stat = eg_intr_md.deq_congest_stat;
        // meta.mirror_md.app_pool_congest_stat = eg_intr_md.app_pool_congest_stat;

        meta.mirror_md.egress_port = egress_port;
        meta.mirror_md.qid = qid;
        meta.mirror_md.mirror_session = (MirrorId_t)1;
        meta.mirror_md.enq_congest_stat = enq_congest_stat;
        meta.mirror_md.deq_congest_stat = deq_congest_stat;
        meta.mirror_md.app_pool_congest_stat = app_pool_congest_stat;

        meta.mirror_md.enq_qdepth = 2;
        meta.mirror_md.deq_qdepth = 3;
        meta.mirror_md.enq_tstamp = 4;
    }
    
    apply {
        // update feedback
        if(meta.pkt_type == PKT_TYPE_NORMAL){
            egress_port = eg_intr_md.egress_port;
            qid = eg_intr_md.egress_qid;
            enq_congest_stat = eg_intr_md.enq_congest_stat;
            deq_congest_stat = eg_intr_md.deq_congest_stat;
            app_pool_congest_stat = eg_intr_md.app_pool_congest_stat;

            // do_feedback_mirror();
        } 
        else if(meta.pkt_type == PKT_TYPE_MIRROR) {
            hdr.feedback.setValid();
            hdr.ethernet.ether_type = ETHERTYPE_FEEDBACK;

            hdr.feedback.egress_port = meta.mirror_md.egress_port;
            hdr.feedback.pad0 = 0;
            hdr.feedback.qid = meta.mirror_md.qid;
            hdr.feedback.pad1 = 0;
            hdr.feedback.enq_congest_stat = meta.mirror_md.enq_congest_stat;
            hdr.feedback.deq_congest_stat = meta.mirror_md.deq_congest_stat;
            hdr.feedback.app_pool_congest_stat = meta.mirror_md.app_pool_congest_stat;

            hdr.feedback.enq_qdepth = meta.mirror_md.enq_qdepth;
            hdr.feedback.deq_qdepth = meta.mirror_md.deq_qdepth;
            hdr.feedback.enq_tstamp = meta.mirror_md.enq_tstamp;
        }
        else if(meta.pkt_type == PKT_TYPE_RTT_MIRROR) {
            hdr.rtt_probe.rtt_opt = RTT_OPT_REDIRECT;
        }

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
