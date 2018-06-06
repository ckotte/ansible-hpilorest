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
- This module configures network settings of the dedicated network interface only.
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
  ipv4:
    description:
    - Wheter to use IPv4.
    default: true
    choices=['true']
  ipv4_address:
    description:
    - The IPv4 address of the HPE iLO interface.
    default: DHCP
    choices=['DHCP', '<IPv4 address>']
  ipv4_subnet_mask:
    description:
    - The IPv4 subnet mask of the HPE iLO interface.
    sample: 255.255.255.0
  ipv4_gateway:
    description:
    - The IPv4 gateway address of the HPE iLO interface.
    sample: 192.168.1.1
  ipv6:
    description:
    - Wheter to use IPv6.
    - Not fully implemented. Some parts will be enabled/disabled during domain or DNS server configuration.
    default: false
    choices=['false']
  hostname:
    description:
    - The hostname to be configured.
    required: true
    sample: testhost
  domain:
    description:
    - The domain name to be configured.
    - DHCPv4/v6-UseDomainName will be disabled if not set to DHCP. Otherwise, domain name can't be set.
    required: true
    choices=['DHCP', '<domain name>']
    sample: example.com
  dns_server_1:
    description:
    - The first DNS server IP or address to be configured.
    - DHCPv4/v6-UseDNSServers will be enabled if at least one server is set to DHCP.
    required: true
    choices=['DHCP', '<IPv4 address>']
    sample: 192.168.1.3
  dns_server_2:
    description:
    - The second DNS server IP or address to be configured.
    - DHCPv4/v6-UseDNSServers will be enabled if at least one server is set to DHCP.
    required: true
    choices=['DHCP', '<IPv4 address>']
    sample: 192.168.1.4
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


def check_network_setting(module, restobj, ipv4, ipv4_address, ipv4_subnet_mask, ipv4_gateway, ipv6, hostname, domain, dns_server_1, dns_server_2, bios_password=None):
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
        # BL460c blade server:
        #   NIC1: "Dedicated Network Port"
        # DL380 rack server:
        #   NIC1: "Dedicated Network Port"
        #   NIC2: "Shared Network Port"
        #   "NICEnabled": true = "Manager Dedicated Network Interface"
        #   "NICEnabled": false = "Manager Shared Network Interface"
        if instance["href"] == '/rest/v1/Managers/1/EthernetInterfaces/1':
            nic1 = restobj.rest_get(instance["href"])
            # IPv4
            if ipv4:
                if ipv4_address == "DHCP":
                    # Enable DHCPv4
                    if nic1.dict['Oem']['Hp']['DHCPv4']['Enabled'] is not True:
                        would_be_changed.append('DHCPv4')
                        changed_status = True
                    if nic1.dict['Oem']['Hp']['DHCPv4']['UseGateway'] is not True:
                        would_be_changed.append('DHCPv4-UseGateway')
                        changed_status = True
                    if nic1.dict['Oem']['Hp']['DHCPv4']['UseStaticRoutes'] is not True:
                        would_be_changed.append('DHCPv4-UseStaticRoutes')
                        changed_status = True
                    if nic1.dict['Oem']['Hp']['DHCPv4']['UseWINSServers'] is not True:
                        would_be_changed.append('DHCPv4-UseWINSServers')
                        changed_status = True
                    # DNS servers
                    if (dns_server_1 == "DHCP" and dns_server_1 == "DHCP"):
                        if nic1.dict['Oem']['Hp']['DHCPv4']['UseDNSServers'] is not True:
                            would_be_changed.append('DHCPv4-UseDNSServers')
                            changed_status = True
                    else:
                        if (dns_server_1 != "DHCP" and dns_server_1 != "DHCP"):
                            if not ((nic1.dict['Oem']['Hp']['IPv4']['DNSServers'][0] == dns_server_1) and
                               (nic1.dict['Oem']['Hp']['IPv4']['DNSServers'][1] == dns_server_2)):
                                would_be_changed.append('IPv4-DNSServers')
                                changed_status = True
                        else:
                            module.fail_json(msg="Both dns_server_1 and dns_server_2 need to be set to an IPv4 address!")
                    # Domain name
                    if domain == "DHCP":
                        if nic1.dict['Oem']['Hp']['DHCPv4']['UseDomainName'] is not True:
                            would_be_changed.append('DHCPv4-UseDomainName')
                            changed_status = True
                    else:
                        if nic1.dict['Oem']['Hp']['DHCPv4']['UseDomainName'] is not False:
                            would_be_changed.append('DHCPv4-UseDomainName')
                            changed_status = True
                        if nic1.dict['Oem']['Hp']['DomainName'] != domain:
                            would_be_changed.append('DomainName')
                            changed_status = True
                else:
                    # Disable DHCPv4
                    if nic1.dict['Oem']['Hp']['DHCPv4']['Enabled'] is not False:
                        would_be_changed.append('DHCPv4')
                        changed_status = True
                    if nic1.dict['Oem']['Hp']['DHCPv4']['UseGateway'] is not False:
                        would_be_changed.append('DHCPv4-UseGateway')
                        changed_status = True
                    if nic1.dict['Oem']['Hp']['DHCPv4']['UseStaticRoutes'] is not False:
                        would_be_changed.append('DHCPv4-UseStaticRoutes')
                        changed_status = True
                    if nic1.dict['Oem']['Hp']['DHCPv4']['UseWINSServers'] is not False:
                        would_be_changed.append('DHCPv4-UseWINSServers')
                        changed_status = True
                    # Enable IPv4 address, subnet mask, and gateway
                    if nic1.dict['IPv4Addresses'][0]['Address'] != ipv4_address:
                        would_be_changed.append('IPv4-Address')
                        changed_status = True
                    if nic1.dict['IPv4Addresses'][0]['SubnetMask'] != ipv4_subnet_mask:
                        would_be_changed.append('IPv4-SubnetMask')
                        changed_status = True
                    if nic1.dict['IPv4Addresses'][0]['Gateway'] != ipv4_gateway:
                        would_be_changed.append('IPv4-Gateway')
                        changed_status = True
                    # Disable DHCPv4 DNS servers
                    if (dns_server_1 != "DHCP" and dns_server_1 != "DHCP"):
                        if not ((nic1.dict['Oem']['Hp']['IPv4']['DNSServers'][0] == dns_server_1) and
                           (nic1.dict['Oem']['Hp']['IPv4']['DNSServers'][1] == dns_server_2)):
                            would_be_changed.append('IPv4-DNSServers')
                            changed_status = True
                    else:
                        module.fail_json(msg="Both dns_server_1 and dns_server_2 need to be set to an IPv4 address!")
                    # Domain name
                    if domain == "DHCP":
                        module.fail_json(msg="domain can't be set to DHCP if ipv4_address isn't set to DHCP!")
                    else:
                        if nic1.dict['Oem']['Hp']['DHCPv4']['UseDomainName'] is not False:
                            would_be_changed.append('DHCPv4-UseDomainName')
                            changed_status = True
                        if nic1.dict['Oem']['Hp']['DomainName'] != domain:
                            would_be_changed.append('DomainName')
                            changed_status = True
            else:
                module.fail_json(msg="IPv4 can't be disabled. IPv6 isn't fully implemented!")
            # IPv6
            if ipv6:
                module.fail_json(msg="IPv6 isn't fully implemented!")
            else:
                # DHCPv6
                if nic1.dict['Oem']['Hp']['DHCPv6']['StatefulModeEnabled'] is not False:
                    would_be_changed.append('DHCPv6-StatefulModeEnabled')
                    changed_status = True
                if nic1.dict['Oem']['Hp']['DHCPv6']['StatelessModeEnabled'] is not False:
                    would_be_changed.append('DHCPv6-StatelessModeEnabled')
                    changed_status = True
                if nic1.dict['Oem']['Hp']['DHCPv6']['UseRapidCommit'] is not False:
                    would_be_changed.append('DHCPv6-UseRapidCommit')
                    changed_status = True
                if nic1.dict['Oem']['Hp']['DHCPv6']['UseDNSServers'] is not False:
                    would_be_changed.append('DHCPv6-UseDNSServers')
                    changed_status = True
                if nic1.dict['Oem']['Hp']['DHCPv6']['UseDomainName'] is not False:
                    would_be_changed.append('DHCPv6-UseDomainName')
                    changed_status = True
                if nic1.dict['Oem']['Hp']['DHCPv6']['UseNTPServers'] is not False:
                    would_be_changed.append('DHCPv6-NTPServers')
                    changed_status = True
                # IPv6
                if nic1.dict['Oem']['Hp']['IPv6']['SLAACEnabled'] is not False:
                    would_be_changed.append('IPv6-SLAACEnabled')
                    changed_status = True
                if nic1.dict['IPv6AddressPolicyTable'][0]['Precedence'] != 100:
                    would_be_changed.append('IPv6-Precedence')
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


def set_network_setting(module, restobj, ipv4, ipv4_address, ipv4_subnet_mask, ipv4_gateway, ipv6, hostname, domain, dns_server_1, dns_server_2, bios_password=None):
    """Set Network Service setting"""

    changed = []
    pending_reset = False
    changed_status = False
    dhcpv4_setting_changed = False

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
                module.fail_json(msg="Set HostName. Return code %s: %s" % (response.status, message))
        # check if iLO reset is pending
        if network_service.dict['Oem']['Hp']['ConfigurationSettings'] == 'SomePendingReset':
            pending_reset = True

    instances = restobj.search_for_type(module, "EthernetNetworkInterface.")
    for instance in instances:
        if instance["href"] == '/rest/v1/Managers/1/EthernetInterfaces/1':
            nic1 = restobj.rest_get(instance["href"])
            # IPv4
            if ipv4:
                if ipv4_address == "DHCP":
                    # Enable DHCPv4
                    body_dhcpv4 = {}
                    body_oemhp = {}
                    body_oemhp_dhcpv4 = {}
                    if nic1.dict['Oem']['Hp']['DHCPv4']['Enabled'] is not True:
                        body_oemhp_dhcpv4["Enabled"] = True
                        changed.append('DHCPv4-Enabled')
                        changed_status = True
                        dhcpv4_setting_changed = True
                    if nic1.dict['Oem']['Hp']['DHCPv4']['UseGateway'] is not True:
                        body_oemhp_dhcpv4["UseGateway"] = True
                        changed.append('DHCPv4-UseGateway')
                        changed_status = True
                        dhcpv4_setting_changed = True
                    if nic1.dict['Oem']['Hp']['DHCPv4']['UseStaticRoutes'] is not True:
                        body_oemhp_dhcpv4["UseStaticRoutes"] = True
                        changed.append('DHCPv4-UseStaticRoutes')
                        changed_status = True
                        dhcpv4_setting_changed = True
                    if nic1.dict['Oem']['Hp']['DHCPv4']['UseWINSServers'] is not True:
                        body_oemhp_dhcpv4["UseWINSServers"] = True
                        changed.append('DHCPv4-UseWINSServers')
                        changed_status = True
                        dhcpv4_setting_changed = True
                    # DNS servers
                    if (dns_server_1 == "DHCP" and dns_server_1 == "DHCP"):
                        if nic1.dict['Oem']['Hp']['DHCPv4']['UseDNSServers'] is not True:
                            body_oemhp_dhcpv4["UseDNSServers"] = True
                            changed.append('DHCPv4-UseDNSServers')
                            changed_status = True
                            dhcpv4_setting_changed = True
                    else:
                        if (dns_server_1 != "DHCP" and dns_server_1 != "DHCP"):
                            if not ((nic1.dict['Oem']['Hp']['IPv4']['DNSServers'][0] == dns_server_1) and
                               (nic1.dict['Oem']['Hp']['IPv4']['DNSServers'][1] == dns_server_2)):
                                body = {"Oem": {"Hp": {"IPv4": {"DNSServers": [dns_server_1, dns_server_2]}}}}
                                response = restobj.rest_patch(instance["href"], body, optionalpassword=bios_password)
                                message = restobj.message_handler(module, response)
                                if response.status == 200:
                                    changed_status = True
                                    changed.append('IPv4-NameServers')
                                else:
                                    module.fail_json(msg="Set NameServers. Return code %s: %s" % (response.status, message))
                        else:
                            module.fail_json(msg="Both dns_server_1 and dns_server_2 need to be set to an IPv4 address!")
                    # Domain name
                    if domain == "DHCP":
                        if nic1.dict['Oem']['Hp']['DHCPv4']['UseDomainName'] is not True:
                            body_oemhp_dhcpv4["UseDomainName"] = True
                            changed.append('DHCPv4-UseDomainName')
                            changed_status = True
                            dhcpv4_setting_changed = True
                    else:
                        if nic1.dict['Oem']['Hp']['DHCPv4']['UseDomainName'] is not False:
                            body_oemhp_dhcpv4["UseDomainName"] = False
                            changed.append('DHCPv4-UseDomainName')
                            changed_status = True
                        if nic1.dict['Oem']['Hp']['DomainName'] != domain:
                            body = {"Oem": {"Hp": {"DomainName": domain}}}
                            response = restobj.rest_patch(instance["href"], body, optionalpassword=bios_password)
                            message = restobj.message_handler(module, response)
                            if response.status == 200:
                                changed_status = True
                                changed.append('DomainName')
                            else:
                                module.fail_json(msg="Set DomainName. Return code %s: %s" % (response.status, message))
                    # Configure DHCPv4 settings
                    if dhcpv4_setting_changed:
                        if len(body_oemhp_dhcpv4):
                            body_oemhp['DHCPv4'] = body_oemhp_dhcpv4
                        if len(body_oemhp):
                            body_dhcpv4["Oem"] = {"Hp": body_oemhp}
                        response = restobj.rest_patch(instance["href"], body_dhcpv4, optionalpassword=bios_password)
                        message = restobj.message_handler(module, response)
                        if response.status != 200:
                            module.fail_json(msg="Set DHCPv4. Return code %s: %s" % (response.status, message))
                else:
                    # Disable DHCPv4
                    body_dhcpv4 = {}
                    body_oemhp = {}
                    body_oemhp_dhcpv4 = {}
                    if nic1.dict['Oem']['Hp']['DHCPv4']['Enabled'] is not False:
                        body_oemhp_dhcpv4["Enabled"] = False
                        changed.append('DHCPv4-Enabled')
                        changed_status = True
                        dhcpv4_setting_changed = True
                    if nic1.dict['Oem']['Hp']['DHCPv4']['UseGateway'] is not False:
                        body_oemhp_dhcpv4["UseGateway"] = False
                        changed.append('DHCPv4-UseGateway')
                        changed_status = True
                        dhcpv4_setting_changed = True
                    if nic1.dict['Oem']['Hp']['DHCPv4']['UseStaticRoutes'] is not False:
                        body_oemhp_dhcpv4["UseStaticRoutes"] = False
                        changed.append('DHCPv4-UseStaticRoutes')
                        changed_status = True
                        dhcpv4_setting_changed = True
                    if nic1.dict['Oem']['Hp']['DHCPv4']['UseWINSServers'] is not False:
                        body_oemhp_dhcpv4["UseWINSServers"] = False
                        changed.append('DHCPv4-UseWINSServers')
                        changed_status = True
                        dhcpv4_setting_changed = True
                    # Enable IPv4 address, subnet mask, and gateway
                    body_ipv4 = {}
                    body_ipv4addresses = {}
                    if nic1.dict['IPv4Addresses'][0]['Address'] != ipv4_address:
                        body_ipv4addresses["Address"] = False
                        changed.append('IPv4-Address')
                        changed_status = True
                        dhcpv4_setting_changed = True
                    if nic1.dict['IPv4Addresses'][0]['SubnetMask'] != ipv4_subnet_mask:
                        body_ipv4addresses["SubnetMask"] = False
                        changed.append('IPv4-SubnetMask')
                        changed_status = True
                        dhcpv4_setting_changed = True
                    if nic1.dict['IPv4Addresses'][0]['Gateway'] != ipv4_gateway:
                        body_ipv4addresses["Gateway"] = False
                        changed.append('IPv4-Gateway')
                        changed_status = True
                        dhcpv4_setting_changed = True
                    # Disable DHCPv4 DNS servers
                    if (dns_server_1 != "DHCP" and dns_server_1 != "DHCP"):
                        if not ((nic1.dict['Oem']['Hp']['IPv4']['DNSServers'][0] == dns_server_1) and
                           (nic1.dict['Oem']['Hp']['IPv4']['DNSServers'][1] == dns_server_2)):
                            body = {"Oem": {"Hp": {"IPv4": {"DNSServers": [dns_server_1, dns_server_2]}}}}
                            response = restobj.rest_patch(instance["href"], body, optionalpassword=bios_password)
                            message = restobj.message_handler(module, response)
                            if response.status == 200:
                                changed_status = True
                                changed.append('IPv4-NameServers')
                            else:
                                module.fail_json(msg="Set NameServers. Return code %s: %s" % (response.status, message))
                    else:
                        module.fail_json(msg="Both dns_server_1 and dns_server_2 need to be set to an IPv4 address!")
                    # Domain name
                    if domain == "DHCP":
                        module.fail_json(msg="Domain can't be set to DHCP if ipv4_address isn't set to DHCP!")
                    else:
                        if nic1.dict['Oem']['Hp']['DHCPv4']['UseDomainName'] is not False:
                            body_oemhp_dhcpv4["UseDomainName"] = False
                            changed.append('DHCPv4-UseDomainName')
                            changed_status = True
                            dhcpv4_setting_changed = True
                        if nic1.dict['Oem']['Hp']['DomainName'] != domain:
                            body = {"Oem": {"Hp": {"DomainName": domain}}}
                            response = restobj.rest_patch(instance["href"], body, optionalpassword=bios_password)
                            message = restobj.message_handler(module, response)
                            if response.status == 200:
                                changed_status = True
                                changed.append('DomainName')
                            else:
                                module.fail_json(msg="Set DomainName. Return code %s: %s" % (response.status, message))
                    if dhcpv4_setting_changed:
                        # Configure DHCPv4 settings
                        if len(body_oemhp_dhcpv4):
                            body_oemhp['DHCPv4'] = body_oemhp_dhcpv4
                        if len(body_oemhp):
                            body_dhcpv4["Oem"] = {"Hp": body_oemhp}
                        response = restobj.rest_patch(instance["href"], body_dhcpv4, optionalpassword=bios_password)
                        message = restobj.message_handler(module, response)
                        if response.status != 200:
                            module.fail_json(msg="Set DHCPv4. Return code %s: %s" % (response.status, message))
                        # Configure IPv4 settings
                        if len(body_ipv4addresses):
                            body_ipv4['IPv4Addresses'] = {[body_ipv4addresses]}
                            response = restobj.rest_patch(instance["href"], body_ipv4, optionalpassword=bios_password)
                            message = restobj.message_handler(module, response)
                            if response.status != 200:
                                module.fail_json(msg="Set IPv4. Return code %s: %s" % (response.status, message))
            else:
                module.fail_json(msg="IPv4 can't be disabled. IPv6 isn't fully implemented!")
            # IPv6
            if ipv6:
                module.fail_json(msg="IPv6 isn't fully implemented!")
            else:
                # DHCPv6
                body_dhcpv6 = {}
                body_oemhp = {}
                body_oemhp_dhcpv6 = {}
                if nic1.dict['Oem']['Hp']['DHCPv6']['StatefulModeEnabled'] is not False:
                    body_oemhp_dhcpv6["StatefulModeEnabled"] = False
                    changed.append('DHCPv6-StatefulModeEnabled')
                    changed_status = True
                if nic1.dict['Oem']['Hp']['DHCPv6']['StatelessModeEnabled'] is not False:
                    body_oemhp_dhcpv6["StatelessModeEnabled"] = False
                    changed.append('DHCPv6-StatelessModeEnabled')
                    changed_status = True
                if nic1.dict['Oem']['Hp']['DHCPv6']['UseRapidCommit'] is not False:
                    body_oemhp_dhcpv6["UseRapidCommit"] = False
                    changed.append('DHCPv6-UseRapidCommit')
                    changed_status = True
                if nic1.dict['Oem']['Hp']['DHCPv6']['UseDNSServers'] is not False:
                    body_oemhp_dhcpv6["UseDNSServers"] = False
                    changed.append('DHCPv6-UseDNSServers')
                    changed_status = True
                if nic1.dict['Oem']['Hp']['DHCPv6']['UseDomainName'] is not False:
                    body_oemhp_dhcpv6["UseDomainName"] = False
                    changed.append('DHCPv6-UseDomainName')
                    changed_status = True
                if nic1.dict['Oem']['Hp']['DHCPv6']['UseNTPServers'] is not False:
                    body_oemhp_dhcpv6["UseNTPServers"] = False
                    changed.append('DHCPv6-UseNTPServers')
                    changed_status = True
                if changed_status:
                    if len(body_oemhp_dhcpv6):
                        body_oemhp['DHCPv6'] = body_oemhp_dhcpv6
                    if len(body_oemhp):
                        body_dhcpv6["Oem"] = {"Hp": body_oemhp}
                    response = restobj.rest_patch(instance["href"], body_dhcpv6, optionalpassword=bios_password)
                    message = restobj.message_handler(module, response)
                    if response.status != 200:
                        module.fail_json(msg="Disable DHCPv6. Return code %s: %s" % (response.status, message))
                # IPv6
                if nic1.dict['Oem']['Hp']['IPv6']['SLAACEnabled'] is not False:
                    body = {"Oem": {"Hp": {"IPv6": {"SLAACEnabled": False}}}}
                    response = restobj.rest_patch(instance["href"], body, optionalpassword=bios_password)
                    message = restobj.message_handler(module, response)
                    if response.status == 200:
                        changed_status = True
                        changed.append('IPv6-SLAACEnabled')
                    else:
                        module.fail_json(msg="Disable DHCPv6-SLAAC. Return code %s: %s" % (response.status, message))
                # IPv6: iLO Client Applications use IPv6 first
                # 35 = enabled
                # 100 = disabled
                if nic1.dict['IPv6AddressPolicyTable'][0]['Precedence'] != 100:
                    body = {"IPv6AddressPolicyTable": [{"Precedence": 100}]}
                    response = restobj.rest_patch(instance["href"], body, optionalpassword=bios_password)
                    message = restobj.message_handler(module, response)
                    if response.status == 200:
                        changed_status = True
                        changed.append('IPv6-Precedence')
                    else:
                        module.fail_json(msg="Disable IPv6-Precedence. Return code %s: %s" % (response.status, message))
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
            ipv4=dict(default=True, type='bool'),
            ipv4_address=dict(default='DHCP', type='str'),
            ipv4_subnet_mask=dict(type='str'),
            ipv4_gateway=dict(type='str'),
            ipv6=dict(default=False, type='bool'),
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
    ipv4 = module.params['ipv4']
    ipv4_address = module.params['ipv4_address']
    ipv4_subnet_mask = module.params['ipv4_subnet_mask']
    ipv4_gateway = module.params['ipv4_gateway']
    ipv6 = module.params['ipv6']
    hostname = module.params['hostname']
    domain = module.params['domain']
    dns_server_1 = module.params['dns_server_1']
    dns_server_2 = module.params['dns_server_2']

    ilo_url = "https://" + ilo_hostname

    # # Create a REST object
    REST_OBJ = RestObject(module, ilo_url, ilo_login, ilo_password)

    if module.check_mode:
        check_network_setting(module, REST_OBJ, ipv4, ipv4_address, ipv4_subnet_mask, ipv4_gateway, ipv6, hostname, domain, dns_server_1, dns_server_2)

    set_network_setting(module, REST_OBJ, ipv4, ipv4_address, ipv4_subnet_mask, ipv4_gateway, ipv6, hostname, domain, dns_server_1, dns_server_2)


if __name__ == '__main__':
    main()
