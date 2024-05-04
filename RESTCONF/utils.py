import requests
import sys
import ipaddress
from collections import OrderedDict

requests.packages.urllib3.disable_warnings()
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

HOST = "devnetsandboxiosxe.cisco.com"
USER = "admin"
PASS = "C1sco12345"

def get_configured_interfaces():
    url = "https://{h}/restconf/data/ietf-interfaces:interfaces".format(h=HOST)
    headers = {'Content-Type': 'application/yang-data+json',
               'Accept': 'application/yang-data+json'}
    try:
        response = requests.get(url, auth=(USER, PASS), headers=headers, verify=False)
        response.raise_for_status()
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    # print(response.text)
    return response.json()["ietf-interfaces:interfaces"]["interface"]

def print_configured_interfaces(interfaces):
    for interface in interfaces:
        print(interface["name"], interface["ietf-ip:ipv4"])

def get_interface_details(interface):
    url = "https://{h}/restconf/data/ietf-interfaces:interfaces".format(h=HOST)
    interface_url = url + "/interface={i}".format(i=interface)
    headers = {'Content-Type': 'application/yang-data+json',
               'Accept': 'application/yang-data+json'}
    try:
        response = requests.get(interface_url, auth=(USER, PASS), headers=headers, verify=False)
        response.raise_for_status()
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    intf = response.json()["ietf-interfaces:interface"]
    return intf

def print_interface_details(intf, cidr=False):
    print("Name: ", intf[0]["name"])
    try:
        netmask = intf[0]["ietf-ip:ipv4"]["address"][0]["netmask"]
        if cidr:
            nma = ipaddress.ip_address(netmask)
            netmask = str("{0:b}".format(int(nma)).count('1'))
        print("IP Address: ", intf[0]["ietf-ip:ipv4"]["address"][0]["ip"], "/",
              netmask)
    except KeyError:
        print("IP Address: UNCONFIGURED")
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)

def create_interface(interface, ip):
    url = "https://{h}/restconf/data/ietf-interfaces:interfaces".format(h=HOST)

    interface_data = {
        "ietf-interfaces:interface": {
            "name": interface,
            "description": "Configured by RESTCONF",
            "type": "iana-if-type:softwareLoopback",
            "enabled": True,
            "ietf-ip:ipv4": {
                "address": [
                    {
                        "ip": ip["address"],
                        "netmask": ip["mask"]
                    }
                ]
            }
        }
    }

    # interface_data = OrderedDict([('ietf-interfaces:interface',
    #           OrderedDict([
    #                         ('name', interface),
    #                         ('description', 'Configured by RESTCONF'),
    #                         ('type', 'iana-if-type:ethernetCsmacd'),
    #                         ('enabled', True),
    #                         ('ietf-ip:ipv4',
    #                             OrderedDict([
    #                               ('address', [OrderedDict([
    #                                   ('ip', ip["address"]),
    #                                   ('netmask', ip["mask"])
    #                               ])]
    #                               )
    #                             ])
    #                         ),
    #                       ])
    #                     )])

    headers = {
        'Content-Type': 'application/yang-data+json',
        'Accept': 'application/yang-data+json'
    }
    
    try:
        response = requests.post(url, headers=headers, auth=(USER, PASS), json=interface_data, verify=False)
        response.raise_for_status()
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    
    print(response.text)

def configure_ip_address(interface, ip):
    url = "https://{h}/restconf/data/ietf-interfaces:interfaces".format(h=HOST)
    interface_url = url + "/interface={i}".format(i=interface)

    # Create the data payload to reconfigure IP address
    # Need to use OrderedDicts to maintain the order of elements
    data = OrderedDict([('ietf-interfaces:interface',
              OrderedDict([
                            ('name', interface),
                            ('type', 'iana-if-type:ethernetCsmacd'),
                            ('ietf-ip:ipv4',
                                OrderedDict([
                                  ('address', [OrderedDict([
                                      ('ip', ip["address"]),
                                      ('netmask', ip["mask"])
                                  ])]
                                  )
                                ])
                            ),
                          ])
                        )])

    # Use PUT request to update data
    headers = {'Content-Type': 'application/yang-data+json',
               'Accept': 'application/yang-data+json'}
    try:
        response = requests.put(interface_url,auth=(USER, PASS),headers=headers,verify=False,json=data)
        response.raise_for_status()
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    print(response.text)


def get_hostname():
    url = "https://{h}/restconf/data/Cisco-IOS-XE-native:native/hostname".format(h=HOST)

    headers = {'Content-Type': 'application/yang-data+json',
               'Accept': 'application/yang-data+json'}
    response = requests.request("GET", url, auth=(USER, PASS), headers=headers, verify=False)
    print(response.text)

def put_hostname():
    url = "https://{h}/restconf/data/Cisco-IOS-XE-native:native/hostname".format(h=HOST)
    payload = "{\"hostname\": \"CATALYST9300\"}"

    headers = {'Content-Type': 'application/yang-data+json',
               'Accept': 'application/yang-data+json'}
    response = requests.request("PUT", url, auth=(USER, PASS),
                            data=payload, headers=headers, verify=False)
    print(response.text)

def get_network_configs():
    url = "https://{h}/restconf/data/Cisco-IOS-XE-native:native".format(h=HOST)
    headers = {
       "Content-Type": "application/yang-data+json",
       "Accept": "application/yang-data+json",
    }
    try:
        response = requests.request("GET", url, headers=headers, auth=(USER, PASS), verify=False)
        response.raise_for_status()
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    print(response.text)

def get_inventory_devices_serial_numbers():
    url = "https://{h}/restconf/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware".format(h=HOST)
    inv_cache = {}
    hosts = [HOST]
    for host in hosts:
        u = url.format(host)
        headers = {
            'Accept': "application/yang-data+json",
        }
        response = None
        try:
            response = requests.request('GET', u, auth=(USER, PASS), headers=headers, verify=False)
            response.raise_for_status()
        except Exception as e:
            print('Failed to get inventory from device: {}'.format(e))
            continue
        inv = response.json()
        for asset in inv['Cisco-IOS-XE-device-hardware-oper:device-hardware']['device-inventory']:
            if host not in inv_cache:
                inv_cache[host] = []
            if asset['serial-number'] == '':
                continue
            inv_cache[host].append(
                {'sn': asset['serial-number'], 'pn': asset['part-number']})
    for host, comps in inv_cache.items():
        print('Host {} serial numbers:'.format(host))
        for comp in comps:
            print('\t{}'.format(comp['sn']))

def main():
    interfaces = get_configured_interfaces()
    print_configured_interfaces(interfaces)

    # ip = {
    #     "address": "10.10.10.2",
    #     "mask": "255.255.255.0"
    # }
    # create_interface("Loopback21", ip)

if __name__ == '__main__':
    sys.exit(main())