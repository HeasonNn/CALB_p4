/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

parser IngressParser(
    packet_in                               pkt,
    out     headers_t                       hdr,
    out     my_ingress_metadata_t           meta,
    out     ingress_intrinsic_metadata_t    ig_intr_md)
{
    Checksum() ipv4_checksum;
    
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    state meta_init {
        meta.ipv4_csum_err  = 0;
        meta.ingress_port   = ig_intr_md.ingress_port;
        meta.egress_port    = 100; // Select an unused port as the initial value of egress_port
        meta.device_type    = 0;
        meta.hash_10        = 0;

        meta.pkt_type       = 0;
        meta.gen_rtt_probe  = 0;
        meta.rtt_val        = 0;
        meta.rtt_timestamp0 = 0;
        meta.bypass         = 0;

        //debug
        meta.reg_val        = 0;
        meta.reg_result     = 0;

        meta.debug_val1     = 0;
        meta.debug_val2     = 0;
        
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
        rtt_probe_h  rtt_probe_hdr = pkt.lookahead<rtt_probe_h>();
        transition select(rtt_probe_hdr.rtt_opt) {
            (bit<2>) 1:       parse_rtt_probe;
            (bit<2>) 2:       parse_rtt_probe;
            (bit<2>) 3:       parse_rtt_probe;
            default: accept;
        }
    }
    
    state parse_rtt_probe {
        pkt.extract(hdr.rtt_probe);
        transition accept;
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(
    packet_out                                          pkt,
    inout   headers_t                                   hdr,
    in      my_ingress_metadata_t                       meta,
    in      ingress_intrinsic_metadata_for_deparser_t   ig_dprsr_md)
{
    Checksum() ipv4_checksum;
    // Digest <feedback_digest_t>() feedback_digest;
    Digest <rtt_digest_t>() rtt_digest;
    Mirror() rtt_mirror;

    apply {
        // if (ig_dprsr_md.digest_type == FEEDBACK_DIGEST) {
        //     feedback_digest.pack({
        //         ig_dprsr_md.digest_type,
        //         hdr.feedback.enq_qdepth,
        //         hdr.feedback.deq_qdepth,
        //         hdr.feedback.enq_tstamp,
        //         hdr.feedback.egress_port,
        //         hdr.feedback.qid,
        //         hdr.feedback.enq_congest_stat,
        //         hdr.feedback.deq_congest_stat,
        //         hdr.feedback.app_pool_congest_stat
        //     });
        // }

        if(ig_dprsr_md.digest_type == RTT_DIGEST) {
            rtt_digest.pack({
                meta.debug_val1,
                ig_dprsr_md.digest_type,
                meta.hash_10,
                meta.rtt_val,
                meta.debug_val2
            });
        }

        if(ig_dprsr_md.mirror_type == MIRROR_TYPE_I2E) {
            rtt_mirror.emit<rtt_mirror_h>(meta.rtt_mirror_session, {
                meta.pkt_type,
                0,
                meta.rtt_mirror_session
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
        pkt.emit(hdr.rtt_probe);
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

parser EgressParser(
    packet_in                               pkt,
    out     headers_t                       hdr,
    out     my_egress_metadata_t            meta,
    out     egress_intrinsic_metadata_t     eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        transition parser_metadata;
    }

    state parser_metadata {
        pkt_type_t  pkt_type = pkt.lookahead<pkt_type_t>();
        transition select(pkt_type) {
            PKT_TYPE_MIRROR: parse_mirror_md;
            PKT_TYPE_RTT_MIRROR: parse_rtt_mirror_md;
            default: parse_normal_md;
        }
    }
    
    state parse_mirror_md {
        pkt.extract(meta.mirror_md);
         meta.pkt_type = meta.mirror_md.pkt_type;
        transition parse_ethernet;
    }

    state parse_rtt_mirror_md {
        pkt.extract(meta.rtt_mirror_md);
        meta.pkt_type = meta.rtt_mirror_md.pkt_type;
        transition parse_ethernet;
    }

    state parse_normal_md {
        meta.pkt_type = PKT_TYPE_NORMAL;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:     parse_ipv4;
            default:            accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition parse_tcp;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        rtt_probe_h  rtt_probe_hdr = pkt.lookahead<rtt_probe_h>();
        transition select(rtt_probe_hdr.rtt_opt) {
            (bit<2>) 1:       parse_rtt_probe;
            (bit<2>) 2:       parse_rtt_probe;
            (bit<2>) 3:       parse_rtt_probe;
            default: accept;
        }
    }
    
    state parse_rtt_probe {
        pkt.extract(hdr.rtt_probe);
        transition accept;
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(
    packet_out                                          pkt,
    inout   headers_t                                   hdr,
    in      my_egress_metadata_t                        meta,
    in      egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md)
{
    Mirror() mirror;

    apply {
        if(eg_dprsr_md.mirror_type == MIRROR_TYPE_E2E) {
            mirror.emit<mirror_h>(
                meta.mirror_md.mirror_session, 
                {   
                    // meta.mirror_md

                    meta.mirror_md.pkt_type,
                    meta.mirror_md.egress_port,
                    meta.mirror_md.qid,
                    meta.mirror_md.pad0,
                    meta.mirror_md.mirror_session,
                    meta.mirror_md.pad1,
                    meta.mirror_md.enq_congest_stat,
                    meta.mirror_md.deq_congest_stat,
                    meta.mirror_md.app_pool_congest_stat,

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
        pkt.emit(hdr.rtt_probe);
    }
}
