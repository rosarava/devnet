import requests

requests.packages.urllib3.disable_warnings()

host = "devnetsandboxiosxe.cisco.com"
port = "443"
username = "admin"
password = "C1sco12345"

url = "https://{}:{}/restconf/data/Cisco-IOS-XE-interfaces-oper:interfaces/interface=GigabitEthernet1".format(host, port)

headers = {
    "Content-Type": "application/yang-data+json",
    "Accept": "application/yang-data+json"
}

res = requests.get(url, auth=(username, password), headers=headers, verify=False)
print(res.text)