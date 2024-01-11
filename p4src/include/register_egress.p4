Register<rtt_probe_reg_t, bit<10>>(1024) rtt_probe_reg; 
RegisterAction<port_reg_t, port_reg_idx_width_t, bit<1>>(port_reg) update_port_reg = {
    void apply(inout port_reg_t reg, out bit<1> result) {
        // reg.congest_stat[1:0] = hdr.feedback.enq_congest_stat;
        // reg.congest_stat[3:2] = hdr.feedback.deq_congest_stat;
        // reg.congest_stat[11:4] = hdr.feedback.app_pool_congest_stat;
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