Register<port_reg_t, port_reg_idx_width_t>(REG_IDX_SIZE) port_reg; 
RegisterAction<port_reg_t, port_reg_idx_width_t, bit<1>>(port_reg) update_port_reg = {
    void apply(inout port_reg_t reg, out bit<1> result) {
        if(hdr.feedback.enq_congest_stat != 0x00 || hdr.feedback.deq_congest_stat != 0x00) {
            result = 1;
            reg.congest_stat = 1;
        } else {
            result = 0;
        }
    }
};
RegisterAction<port_reg_t, port_reg_idx_width_t, bit<1>>(port_reg) check_port_reg = {
    void apply(inout port_reg_t reg, out bit<1> result) { 
        if(reg.congest_stat == 1) {
            result = 1;
        } else{
            result = 0;
        }
    }
};
RegisterAction<port_reg_t, port_reg_idx_width_t, bit<1>>(port_reg) reset_port_reg = {
    void apply(inout port_reg_t reg, out bit<1> result) { 
        reg.congest_stat = 0;
        result = 0;
    }
};
action do_update_port_reg(port_reg_idx_width_t port_reg_index) {
    meta.reg_result = update_port_reg.execute(port_reg_index);
}
action do_check_port_reg(port_reg_idx_width_t port_reg_index) {
    meta.reg_result = check_port_reg.execute(port_reg_index);
}
action do_reset_port_reg(port_reg_idx_width_t port_reg_index) {
    reset_port_reg.execute(port_reg_index);
}

Register<bit<32>, bit<10>>(1024) rtt_probe_reg; 
RegisterAction<bit<32>, bit<10>, bit<32>>(rtt_probe_reg) reset_rtt_probe_reg = {
    void apply(inout bit<32> reg, out bit<32> timestamp) {
        reg = ig_intr_md.ingress_mac_tstamp[31:0];
        timestamp = reg;
    }
};
RegisterAction<bit<32>, bit<10>, bit<32>>(rtt_probe_reg) read_rtt_probe_reg = {
    void apply(inout bit<32> reg, out bit<32> timestamp) {
        timestamp = reg;
    }
}; 
RegisterAction<bit<32>, bit<10>, bit<32>>(rtt_probe_reg) calc_rtt_val = {
    void apply(inout bit<32> reg, out bit<32> rtt_val) {
        rtt_val = ig_intr_md.ingress_mac_tstamp[31:0] - reg;
    }
};
action do_read_rtt_probe_reg() {
    meta.rtt_timestamp0 = read_rtt_probe_reg.execute(meta.hash_10);
}
action do_reset_rtt_probe_reg() {
    meta.rtt_timestamp0 = reset_rtt_probe_reg.execute(meta.hash_10);
}
action do_calc_rtt_val() {
    meta.rtt_val = calc_rtt_val.execute(meta.hash_10);
}

Register<bit<32>, bit<10>>(1024) rtt_interval_reg; 
RegisterAction<bit<32>, bit<10>, bit<32>>(rtt_interval_reg) reset_rtt_interval_reg_action = {
    void apply(inout bit<32> reg, out bit<32> timestamp) {
        reg = ig_intr_md.ingress_mac_tstamp[31:0];
        timestamp = reg;
    }
};
RegisterAction<bit<32>, bit<10>, bit<32>>(rtt_interval_reg) read_rtt_interval_reg_action = {
    void apply(inout bit<32> reg, out bit<32> timestamp) {
        reg = ig_intr_md.ingress_mac_tstamp[31:0];
        timestamp = reg;
    }
};
action do_read_rtt_probe_reg() {
    meta.rtt_timestamp1 = read_rtt_interval_reg_action.execute(meta.hash_10);
}
action do_reset_rtt_probe_reg() {
    meta.rtt_timestamp1 = reset_rtt_interval_reg_action.execute(meta.hash_10);
}