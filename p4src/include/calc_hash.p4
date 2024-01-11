control calc_ipv4_hash(
    in    headers_t                 hdr,
    out   bit<32>                   hash)(
    CRCPolynomial<bit<32>>          poly)
{
    //@symmetric("hdr.ipv4.src_addr", "hdr.ipv4.dst_addr")
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly) hash_algo;

    action do_hash() {
        hash = hash_algo.get({
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4.protocol,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort
            });
    }

    apply {
        do_hash();
    }
}

control calc_ipv4_hashes(
    in    headers_t                 hdr,
    inout selector_hash_t           hash)
{
    calc_ipv4_hash(CRCPolynomial<bit<32>>(
            coeff=32w0x04C11DB7, reversed=true, msb=false, extended=false,
            init=32w0xFFFFFFFF, xor=32w0xFFFFFFFF))
    hash1;
    
#if HASH_WIDTH > 32
    calc_ipv4_hash(CRCPolynomial<bit<32>>(
            coeff=32w0x1EDC6F41, reversed=true, msb=false, extended=false,
            init=32w0xFFFFFFFF, xor=32w0xFFFFFFFF))
    hash2;
    
#if HASH_WIDTH > 64
    calc_ipv4_hash(CRCPolynomial<bit<32>>(
            coeff=32w0xA833982B, reversed=true, msb=false, extended=false,
            init=32w0xFFFFFFFF, xor=32w0xFFFFFFFF))
    hash3;
#endif
#endif

    apply {
        hash1.apply(hdr, hash[31:0]);
#if HASH_WIDTH > 32
        hash2.apply(hdr, hash[63:32]);
#if HASH_WIDTH > 64
        hash3.apply(hdr, hash[95:64]);
#endif
#endif
    }
}

control calc_reg_hash(
    in      headers_t               hdr,
    inout   bit<32>                 hash)
{
    calc_ipv4_hash(CRCPolynomial<bit<32>>(
            coeff=32w0x04C11DB7, reversed=true, msb=false, extended=false,
            init=32w0xFFFFFFFF, xor=32w0xFFFFFFFF))
    hash1;

    apply {
        hash1.apply(hdr, hash[31:0]);
    }
}

control calc_rtt_reply_hash(
    in    headers_t                 hdr,
    out   bit<32>                   hash)(
    CRCPolynomial<bit<32>>          poly)
{
    //@symmetric("hdr.ipv4.src_addr", "hdr.ipv4.dst_addr")
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly) hash_algo;

    action do_hash() {
        hash = hash_algo.get({
                hdr.ipv4.dst_addr,
                hdr.ipv4.src_addr,
                hdr.ipv4.protocol,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort
            });
    }

    apply {
        do_hash();
    }
}

control calc_rtt_hash(
    in      headers_t               hdr,
    inout   bit<32>                 hash)
{
    calc_rtt_reply_hash(CRCPolynomial<bit<32>>(
            coeff=32w0x04C11DB7, reversed=true, msb=false, extended=false,
            init=32w0xFFFFFFFF, xor=32w0xFFFFFFFF))
    hash1;

    apply {
        hash1.apply(hdr, hash[31:0]);
    }
}