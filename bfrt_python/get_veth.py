import psutil

def get_veth_macs():
    veth_macs = dict()
    for interface, addresses in psutil.net_if_addrs().items():
        if interface.startswith('veth'):
            for address in addresses:
                if address.family == psutil.AF_LINK:
                    veth_macs[interface] = address.address
    return veth_macs

veth_macs = get_veth_macs()
for interface, mac_address in veth_macs.items():
    print(f"Interface: {interface}")
    print(f"MAC Address: {mac_address}")
    print()