import sys
from ncclient import manager
import xml.dom.minidom

HOST = "devnetsandboxiosxe.cisco.com"
USER = "admin"
PASS = "C1sco12345"

def get_configs(client):
    # This function retrieves entire configuration from a network element via NETCONF
    # prints it out in a "pretty" XML tree.
    hostname_filter = '''
                      <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                          <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
                          </native>
                      </filter>
                      '''
    # Pretty print the XML reply
    xmlDom = xml.dom.minidom.parseString(str(client.get_config('running', hostname_filter)))
    print(xmlDom.toprettyxml( indent = "  " ))

def update_hostname(client, hostname):
    data = '''
        <config>
            <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
            <hostname>{h}</hostname>
            </native>
        </config>
    '''.format(h=hostname)
    xmlDom = xml.dom.minidom.parseString(str(client.edit_config(data, target='running')))
    print(xmlDom.toprettyxml( indent = "  " ))

def get_entity(client):
    # This function fail to execute
    entity_filter = '''
        <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <ENTITY-MIB xmlns="urn:ietf:params:xml:ns:yang:smiv2:ENTITY-MIB"/>
        </filter>
    '''
    try:
        c = client.get(entity_filter).data_xml
        print(xml.dom.minidom.parseString(c).toprettyxml())
    except Exception as e:
        print('Failed to execute <get> RPC: {}'.format(e))
       
def main():
    client = manager.connect(host=HOST, username=USER, password=PASS, device_params={"name":"csr"})
    get_entity(client)

if __name__ == '__main__':
    sys.exit(main())