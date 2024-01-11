ovs-vsctl add-br s1
ovs-vsctl add-br s2
ovs-vsctl add-br s3

ovs-vsctl add-port s1 veth3
ovs-vsctl add-port s1 veth9

ovs-vsctl add-port s2 veth5
ovs-vsctl add-port s2 veth11

ovs-vsctl add-port s3 veth7
ovs-vsctl add-port s3 veth13

ovs-ofctl del-flows s1
ovs-ofctl del-flows s2
ovs-ofctl del-flows s3

ovs-ofctl add-flow s1 table=0,in_port=veth3,actions=output:veth9
ovs-ofctl add-flow s1 table=0,in_port=veth9,actions=output:veth3
ovs-ofctl add-flow s2 table=0,in_port=veth5,actions=output:veth11
ovs-ofctl add-flow s2 table=0,in_port=veth11,actions=output:veth5
ovs-ofctl add-flow s3 table=0,in_port=veth7,actions=output:veth13
ovs-ofctl add-flow s3 table=0,in_port=veth13,actions=output:veth7

# ovs-appctl bridge/dump-flows s1
# ovs-appctl bridge/dump-flows s2
# ovs-appctl bridge/dump-flows s3

# sysctl -w net.ipv4.conf.veth1.accept_local=1
# sysctl -w net.ipv4.conf.veth15.accept_local=1