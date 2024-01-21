import os
from ipaddress import ip_address

os.environ['SDE'] = "/".join(os.environ['PATH'].split(":")[0].split("/"))
os.environ['SDE_INSTALL'] = "/".join([os.environ['SDE'], 'install'])
print("%env SDE         {}".format(os.environ['SDE']))
print("%env SDE_INSTALL {}".format(os.environ['SDE_INSTALL']))

p4 = bfrt.loadbalance.pipe

# Clear All tables
def clear_all():
    global p4

    # Clear Match Tables
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['MATCH_DIRECT', 'MATCH_INDIRECT_SELECTOR']: 
            print("Clearing table {}".format(table['full_name']))
            for entry in table['node'].get(regex=True):
                entry.remove()
    # Clear Selectors
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['SELECTOR']:
            print("Clearing ActionSelector {}".format(table['full_name']))
            for entry in table['node'].get(regex=True):
                entry.remove()
    # Clear Action Profiles
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['ACTION_PROFILE']:
            print("Clearing ActionProfile {}".format(table['full_name']))
            for entry in table['node'].get(regex=True):
                entry.remove()

clear_all()

# device_type
SRCTOR = 1
DSTTOR = 2
device_type = p4.Ingress.device_type
device_type.add_with_update_device_type(ingress_port=0, egress_port=1, device_type=SRCTOR)
device_type.add_with_update_device_type(ingress_port=0, egress_port=2, device_type=SRCTOR)
device_type.add_with_update_device_type(ingress_port=0, egress_port=3, device_type=SRCTOR)

device_type.add_with_update_device_type(ingress_port=4, egress_port=7, device_type=DSTTOR)
device_type.add_with_update_device_type(ingress_port=5, egress_port=7, device_type=DSTTOR)
device_type.add_with_update_device_type(ingress_port=6, egress_port=7, device_type=DSTTOR)

device_type.add_with_update_device_type(ingress_port=7, egress_port=4, device_type=SRCTOR)
device_type.add_with_update_device_type(ingress_port=7, egress_port=5, device_type=SRCTOR)
device_type.add_with_update_device_type(ingress_port=7, egress_port=6, device_type=SRCTOR)

device_type.add_with_update_device_type(ingress_port=1, egress_port=0, device_type=DSTTOR)
device_type.add_with_update_device_type(ingress_port=2, egress_port=0, device_type=DSTTOR)
device_type.add_with_update_device_type(ingress_port=3, egress_port=0, device_type=DSTTOR)

# ipv4_host
ipv4_host = p4.Ingress.ipv4_host
ipv4_host.add_with_set_nexthop(ingress_port=7, dst_addr=ip_address('20.0.0.1'), nexthop=201)
ipv4_host.add_with_set_nexthop(ingress_port=0, dst_addr=ip_address('20.0.0.2'), nexthop=202)

ipv4_host.add_with_set_nexthop(ingress_port=1, dst_addr=ip_address('20.0.0.1'), nexthop=203)
ipv4_host.add_with_set_nexthop(ingress_port=2, dst_addr=ip_address('20.0.0.1'), nexthop=203)
ipv4_host.add_with_set_nexthop(ingress_port=3, dst_addr=ip_address('20.0.0.1'), nexthop=203)

ipv4_host.add_with_set_nexthop(ingress_port=4, dst_addr=ip_address('20.0.0.2'), nexthop=204)
ipv4_host.add_with_set_nexthop(ingress_port=5, dst_addr=ip_address('20.0.0.2'), nexthop=204)
ipv4_host.add_with_set_nexthop(ingress_port=6, dst_addr=ip_address('20.0.0.2'), nexthop=204)

print("Successfully added ipv4_host entry")

# ipv4_lpm
ipv4_lpm = p4.Ingress.ipv4_lpm
ipv4_lpm.add_with_set_nexthop(dst_addr=ip_address('30.0.0.0'), dst_addr_p_length=16, nexthop=0) # drop
ipv4_lpm.add_with_set_nexthop(dst_addr=ip_address('30.0.1.0'), dst_addr_p_length=24, nexthop=1) # cpu
ipv4_lpm.set_default_with_set_nexthop(nexthop=0)
print("Successfully added ipv4_lpm entry")

# redirect_rtt_probe
RTT_OPT_ECHO     = 1
RTT_OPT_REPLY    = 2
RTT_OPT_REDIRECT = 3
redirect_rtt_probe = p4.Ingress.redirect_rtt_probe
redirect_rtt_probe.add_with_redirect_to_src(ingress_port=68, dst_addr=ip_address('20.0.0.1'), rtt_opt=RTT_OPT_REDIRECT, new_ingress_port=0)
redirect_rtt_probe.add_with_redirect_to_src(ingress_port=68, dst_addr=ip_address('20.0.0.2'), rtt_opt=RTT_OPT_REDIRECT, new_ingress_port=7)

# action profile
ecmp      = p4.Ingress.ecmp
port_0    = 0;    ecmp.add_with_send(port_0, port=0)
port_7    = 7;    ecmp.add_with_send(port_7, port=7)

port_1    = 1;    ecmp.add_with_send(port_1, port=1)
port_2    = 2;    ecmp.add_with_send(port_2, port=2)
port_3    = 3;    ecmp.add_with_send(port_3, port=3)

port_4    = 4;    ecmp.add_with_send(port_4, port=4)
port_5    = 5;    ecmp.add_with_send(port_5, port=5)
port_6    = 6;    ecmp.add_with_send(port_6, port=6)

port_64   = 64;   ecmp.add_with_send(port_64, port=64)
port_drop = 256;  ecmp.add_with_drop(port_drop, 0)
print("Successfully added action profile entry")

# action selector
ecmp_sel = p4.Ingress.ecmp_sel
selector_group1 = 1
ecmp_sel.entry(SELECTOR_GROUP_ID=selector_group1,
               MAX_GROUP_SIZE=8,
               ACTION_MEMBER_ID=[port_1, port_2, port_3],
               ACTION_MEMBER_STATUS=[True, True, True]).push()
selector_group2 = 2
ecmp_sel.entry(SELECTOR_GROUP_ID=selector_group2,
               MAX_GROUP_SIZE=8,
               ACTION_MEMBER_ID=[port_4, port_5, port_6],
               ACTION_MEMBER_STATUS=[True, True, True]).push()
print("Successfully added action selector entry")

# nexthop
nexthop = p4.Ingress.nexthop
nexthop.add(nexthop_id=201, SELECTOR_GROUP_ID=selector_group2)
nexthop.add(nexthop_id=202, SELECTOR_GROUP_ID=selector_group1)
nexthop.add(nexthop_id=203, ACTION_MEMBER_ID=port_0)
nexthop.add(nexthop_id=204, ACTION_MEMBER_ID=port_7)
nexthop.add(nexthop_id=0,   ACTION_MEMBER_ID=port_drop)
nexthop.add(nexthop_id=1,   ACTION_MEMBER_ID=port_64)
print("Successfully added nexthop entry")

# add mirror session
bfrt.mirror.cfg.add_with_normal(sid=1, session_enable=True, direction='BOTH', ucast_egress_port=68, ucast_egress_port_valid=True, max_pkt_len=16000)
print("Successfully added mirror session")

# bfrt.complete_operations()

# Final programming
print(""" ******************* PROGAMMING RESULTS ***************** """)
print ("\nTable ipv4_lpm:")
ipv4_lpm.dump(table=True)

# TODO: dump all nexthop ipv4_host action profile action selector tables

p4_digest = p4.IngressDeparser
port_data = dict()
opt_nexthop = []

# def feedback_digest_cb(dev_id, pipe_id, direction, parser_id, session, msg):
#     global p4
#     global port_data
#     global opt_nexthop

#     for digest in msg:
#         print(digest)
#         # port_data[digest["egress_port"]] = digest

#         # # if current port is congest, find a new port for opt_next_hop table
#         # if (digest["enq_congest_stat"] != 0 or digest["deq_congest_stat"] != 0) and digest["egress_port"] in opt_next_hop:
#         #     avail_port = []
#         #     for eg_port_id, eg_port_info in port_data.items():
#         #         if eg_port_info["enq_congest_stat"] == 0 and eg_port_info["deq_congest_stat"] == 0:
#         #             avail_port.append(eg_port_id)
#         #             print("Port %d is not congest" % (eg_port_id))
#         #     print(avail_port)

#         #     # update opt_next_hop enrty
#         #     if len(avail_port) > 0:
#         #         opt_nexthop = p4.Ingress.opt_next_hop
#         #         opt_nexthop.add_with_send(nexthop_id=102, port=avail_port[0])

#     return 0

# try:
#     p4_digest.feedback_digest.callback_deregister()
# except:
#     pass
# finally:
#     print("Deregistering old digest callback (if any)")
# p4_digest.feedback_digest.callback_register(feedback_digest_cb)
# print("Feedback_digest callback registered")

def rtt_digest_cb(dev_id, pipe_id, direction, parser_id, session, msg):
    global p4

    for digest in msg:
        print(digest)

    return 0

try:
    p4_digest.rtt_digest.callback_deregister()
except:
    pass
finally:
    print("Deregistering old digest callback (if any)")
p4_digest.rtt_digest.callback_register(rtt_digest_cb)
print("rtt_digest callback registered")
