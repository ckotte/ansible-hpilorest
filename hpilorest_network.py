#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2018 Christian Kotte <christian.kotte@gmx.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.hpilorest import RestObject

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = r'''
---
module: hpilorest_network
version_added: "n/a"
author: Christian Kotte (@ckotte)
short_description: Configure HPE iLO network settings.
description:
- This module configures HPE iLO network settings.
- This module requires python-ilorest-library python module.
options:
  host:
    description:
    - The HPE iLO hostname/address that is linked to the physical system.
    required: true
  login:
    description:
    - The login name to authenticate to the HPE iLO interface.
    default: Administrator
  password:
    description:
    - The password to authenticate to the HPE iLO interface.
    default: admin
  hostname:
    description:
    - The hostname to be configured.
  domain:
    description:
    - The domain name to be configured.
    - DHCPv6 will be disabled. Otherwise, domain name can't be set.
  dns_server_1:
    description:
    - The first DNS server IP or address to be configured.
  dns_server_2:
    description:
    - The second DNS server IP or address to be configured.
requirements:
- python-ilorest-library
- python >= 2.7.9
notes:
- This module ought to be run from a system that can access the HPE iLO
  interface directly, either by using C(local_action) or using C(delegate_to).
'''

EXAMPLES = r'''
- name: iLO | Configure network
  tags: network
  hpilorest_network:
    host: "{{ inventory_hostname }}"
    login: "{{ hpilo_login }}"
    password: "{{ hpilo_password }}"
    hostname: "{{ inventory_hostname_short }}"
    domain: "{{ dns_domains[0] }}"
    dns_server_1: "{{ dns_servers[0] }}"
    dns_server_2: "{{ dns_servers[1] }}"
  delegate_to: 127.0.0.1
'''

RETURN = '''
# Default return values
'''


def check_network_setting(module, restobj, hostname, domain, dns_server_1, dns_server_2, bios_password=None):
    """Inform the user what would change if the module were run"""

    would_be_changed = []
    pending_reset = False
    changed_status = False

    instances = restobj.search_for_type(module, "ManagerNetworkService.")
    for instance in instances:
        # instance["href"]: /rest/v1/Managers/1/NetworkService
        network_service = restobj.rest_get(instance["href"])
        if network_service.dict['HostName'] != hostname:
            would_be_changed.append('HostName')
            changed_status = True
        # check if iLO reset is pending
        if network_service.dict['Oem']['Hp']['ConfigurationSettings'] == 'SomePendingReset':
            pending_reset = True

    instances = restobj.search_for_type(module, "EthernetNetworkInterface.")
    for instance in instances:
        # NIC1: "Dedicated Network Port"
        # NIC2: "Shared Network Port"
        # "NICEnabled": true = "Manager Dedicated Network Interface"
        # "NICEnabled": false = "Manager Shared Network Interface"
        if instance["href"] == '/rest/v1/Managers/1/EthernetInterfaces/1':
            nic1 = restobj.rest_get(instance["href"])
            # DNS servers
            if not ((nic1.dict['Oem']['Hp']['IPv4']['DNSServers'][0] == dns_server_1) and
               (nic1.dict['Oem']['Hp']['IPv4']['DNSServers'][1] == dns_server_2)):
                would_be_changed.append('NameServers')
                changed_status = True
            # DHCPv6
            if nic1.dict['Oem']['Hp']['DHCPv6']['StatefulModeEnabled'] is not False:
                would_be_changed.append('DHCPv6-StatefulModeEnabled')
                changed_status = True
            if nic1.dict['Oem']['Hp']['DHCPv6']['UseDNSServers'] is not False:
                would_be_changed.append('DHCPv6-UseDNSServers')
                changed_status = True
            if nic1.dict['Oem']['Hp']['DHCPv6']['UseDomainName'] is not False:
                would_be_changed.append('DHCPv6-UseDomainName')
                changed_status = True
            if nic1.dict['Oem']['Hp']['DHCPv6']['StatelessModeEnabled'] is not False:
                would_be_changed.append('DHCPv6-StatelessModeEnabled')
                changed_status = True
            if nic1.dict['Oem']['Hp']['DHCPv6']['UseNTPServers'] is not False:
                would_be_changed.append('DHCPv6-UseNTPServers')
                changed_status = True
            if nic1.dict['Oem']['Hp']['DHCPv6']['UseRapidCommit'] is not False:
                would_be_changed.append('DHCPv6-UseRapidCommit')
                changed_status = True
            # IPv6
            if nic1.dict['Oem']['Hp']['IPv6']['SLAACEnabled'] is not False:
                would_be_changed.append('DHCPv6-SLAACEnabled')
                changed_status = True
            # Domain name
            if nic1.dict['Oem']['Hp']['DomainName'] != domain:
                would_be_changed.append('DomainName')
                changed_status = True
            # check if iLO reset is pending
            if nic1.dict['Oem']['Hp']['ConfigurationSettings'] == 'SomePendingReset':
                pending_reset = True
            break

    if changed_status:
        if len(would_be_changed) > 2:
            message = ', '.join(would_be_changed[:-1]) + ', and ' + str(would_be_changed[-1]) + ' would be changed'
        elif len(would_be_changed) == 2:
            message = ' and '.join(would_be_changed) + ' would be changed'
        elif len(would_be_changed) == 1:
            message = would_be_changed[0] + ' would be changed'
    else:
        message = 'all settings are already configured'

    if pending_reset:
        changed_status = True
        message = message + ' (iLO reset required)'

    module.exit_json(changed=changed_status, msg=message)


def set_network_setting(module, restobj, hostname, domain, dns_server_1, dns_server_2, bios_password=None):
    """Set Network Service setting"""

    changed = []
    pending_reset = False
    changed_status = False

    instances = restobj.search_for_type(module, "ManagerNetworkService.")
    for instance in instances:
        # instance["href"]: /rest/v1/Managers/1/NetworkService
        network_service = restobj.rest_get(instance["href"])
        if network_service.dict['HostName'] != hostname:
            body = {'HostName': hostname}
            response = restobj.rest_patch(instance["href"], body, optionalpassword=bios_password)
            message = restobj.message_handler(module, response)
            if response.status == 200:
                changed_status = True
                changed.append('HostName')
            else:
                module.fail_json(msg="Return code %s: %s" % (response.status, message))
        # check if iLO reset is pending
        if network_service.dict['Oem']['Hp']['ConfigurationSettings'] == 'SomePendingReset':
            pending_reset = True

    instances = restobj.search_for_type(module, "EthernetNetworkInterface.")
    for instance in instances:
        if instance["href"] == '/rest/v1/Managers/1/EthernetInterfaces/1':
            nic1 = restobj.rest_get(instance["href"])
            # DNS servers
            if not ((nic1.dict['Oem']['Hp']['IPv4']['DNSServers'][0] == dns_server_1) and
               (nic1.dict['Oem']['Hp']['IPv4']['DNSServers'][1] == dns_server_2)):
                body = {"Oem": {"Hp": {"IPv4": {"DNSServers": [dns_server_1, dns_server_2]}}}}
                response = restobj.rest_patch(instance["href"], body, optionalpassword=bios_password)
                message = restobj.message_handler(module, response)
                if response.status == 200:
                    changed_status = True
                    changed.append('NameServers')
                else:
                    module.fail_json(msg="Return code %s: %s" % (response.status, message))
            # DHCPv6
            body = {}
            body_oemhp = {}
            body_oemhp_dhcpv6 = {}
            if nic1.dict['Oem']['Hp']['DHCPv6']['StatefulModeEnabled'] is not False:
                body_oemhp_dhcpv6["StatefulModeEnabled"] = False
                changed.append('DHCPv6-StatefulModeEnabled')
                changed_status = True
            if nic1.dict['Oem']['Hp']['DHCPv6']['UseDNSServers'] is not False:
                body_oemhp_dhcpv6["UseDNSServers"] = False
                changed.append('DHCPv6-UseDNSServers')
                changed_status = True
            if nic1.dict['Oem']['Hp']['DHCPv6']['UseDomainName'] is not False:
                body_oemhp_dhcpv6["UseDomainName"] = False
                changed.append('DHCPv6-UseDomainName')
                changed_status = True
            if nic1.dict['Oem']['Hp']['DHCPv6']['StatelessModeEnabled'] is not False:
                body_oemhp_dhcpv6["StatelessModeEnabled"] = False
                changed.append('DHCPv6-StatelessModeEnabled')
                changed_status = True
            if nic1.dict['Oem']['Hp']['DHCPv6']['UseNTPServers'] is not False:
                body_oemhp_dhcpv6["UseNTPServers"] = False
                changed.append('DHCPv6-UseNTPServers')
                changed_status = True
            if nic1.dict['Oem']['Hp']['DHCPv6']['UseRapidCommit'] is not False:
                body_oemhp_dhcpv6["UseRapidCommit"] = False
                changed.append('DHCPv6-UseRapidCommit')
                changed_status = True
            if changed_status:
                if len(body_oemhp_dhcpv6):
                    body_oemhp['DHCPv6'] = body_oemhp_dhcpv6
                if len(body_oemhp):
                    body["Oem"] = {"Hp": body_oemhp}
                response = restobj.rest_patch(instance["href"], body, optionalpassword=bios_password)
                message = restobj.message_handler(module, response)
                if response.status != 200:
                    module.fail_json(msg="Return code %s: %s" % (response.status, message))
            # IPv6
            if nic1.dict['Oem']['Hp']['IPv6']['SLAACEnabled'] is not False:
                body = {"Oem": {"Hp": {"IPv6": {"SLAACEnabled": False}}}}
                response = restobj.rest_patch(instance["href"], body, optionalpassword=bios_password)
                message = restobj.message_handler(module, response)
                if response.status == 200:
                    changed_status = True
                    changed.append('DHCPv6-SLAACEnabled')
                else:
                    module.fail_json(msg="Return code %s: %s" % (response.status, message))
            # Domain name
            if nic1.dict['Oem']['Hp']['DomainName'] != domain:
                body = {"Oem": {"Hp": {"DomainName": domain}}}
                response = restobj.rest_patch(instance["href"], body, optionalpassword=bios_password)
                message = restobj.message_handler(module, response)
                if response.status == 200:
                    changed_status = True
                    changed.append('DomainName')
                else:
                    module.fail_json(msg="Return code %s: %s" % (response.status, message))
            # check if iLO reset is pending
            if nic1.dict['Oem']['Hp']['ConfigurationSettings'] == 'SomePendingReset':
                pending_reset = True
            break

    if changed_status:
        if len(changed) > 2:
            message = ', '.join(changed[:-1]) + ', and ' + str(changed[-1]) + ' changed'
        elif len(changed) == 2:
            message = ' and '.join(changed) + ' changed'
        elif len(changed) == 1:
            message = changed[0] + ' changed'
    else:
        message = 'all settings are already configured'

    if pending_reset:
        changed_status = True
        message = message + ' (iLO reset required)'

    module.exit_json(changed=changed_status, msg=message)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True, type='str'),
            login=dict(default='Administrator', type='str'),
            password=dict(default='admin', type='str', no_log=True),
            hostname=dict(required=True, type='str'),
            domain=dict(required=True, type='str'),
            dns_server_1=dict(required=True, type='str'),
            dns_server_2=dict(required=True, type='str')
        ),
        supports_check_mode=True
    )

    ilo_hostname = module.params['host']
    ilo_login = module.params['login']
    ilo_password = module.params['password']
    hostname = module.params['hostname']
    domain = module.params['domain']
    dns_server_1 = module.params['dns_server_1']
    dns_server_2 = module.params['dns_server_2']

    ilo_url = "https://" + ilo_hostname

    # # Create a REST object
    REST_OBJ = RestObject(module, ilo_url, ilo_login, ilo_password)

    if module.check_mode:
        check_network_setting(module, REST_OBJ, hostname, domain, dns_server_1, dns_server_2)

    set_network_setting(module, REST_OBJ, hostname, domain, dns_server_1, dns_server_2)


if __name__ == '__main__':
    main()
