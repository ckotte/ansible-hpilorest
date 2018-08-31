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
module: hpilorest_facts
version_added: "n/a"
author: Christian Kotte (@ckotte)
short_description: Gather facts through an HPE iLO interface
description:
- This module gathers facts for a specific system using its HPE iLO interface.
  These facts include hardware and network related information useful
  for provisioning (e.g. macaddress, uuid).
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
requirements:
- python-ilorest-library
- python >= 2.7.9
notes:
- This module ought to be run from a system that can access the HPE iLO
  interface directly, either by using C(local_action) or using C(delegate_to).
'''

EXAMPLES = r'''
- name: iLO | Gather facts
  tags: always, facts
  hpilorest_facts:
    host: "{{ inventory_hostname }}"
    login: "{{ hpilo_login }}"
    password: "{{ hpilo_password }}"
  delegate_to: 127.0.0.1
'''

RETURN = r'''
# Typical output of HPE iLO facts for a physical system
hw_bios_version:
    description: BIOS version
    returned: always
    type: string
    sample: P89 v2.42 (04/25/2017)
hw_bios_date:
    description: BIOS date
    returned: always
    type: string
    sample: 04/25/2017
hw_manufacturer:
    description: Hardware manufacturer
    returned: always
    type: string
    sample: HPE
hw_model:
    description: Hardware model
    returned: always
    type: string
    sample: ProLiant DL380 Gen9
hw_processor_model:
    description: Processor model
    returned: always
    type: string
    sample: Intel(R) Xeon(R) CPU E5-2699 v3 @ 2.30GHz
hw_processor_count:
    description: Processor count
    returned: always
    type: string
    sample: 2
hw_memory:
    description: Memory (GiB)
    returned: always
    type: string
    sample: 768
hw_uuid:
    description: UUID
    returned: always
    type: string
    sample: 30467637-3243-5B43-4C35-34353579324F
hw_uuid:
    description: Hardware UUID
    returned: always
    type: string
    sample: 123456ABC78901D2
hw_serial_number:
    description: Serial number
    returned: always
    type: string
    sample: ABC5459Z5A
hw_sku:
    description: SKU
    returned: always
    type: string
    sample: 123456-A12
hw_asset_tag:
    description: Asset Tag
    returned: always
    type: string
    sample: n/a
hw_power_state:
    description: Power state
    returned: always
    type: string
    sample: On
hw_post_state:
    description: POST state
    returned: always
    type: string
    sample: FinishedPost
hw_health:
    description: Power state
    returned: always
    type: string
    sample: OK
hw_ethX:
    description: Network interface information (for each interface)
    returned: always
    type: dictionary
    sample:
      - macaddress: 00:11:22:33:44:55
        macaddress_dash: 00-11-22-33-44-55
hw_hostname:
    description: Hostname set in the Operating System
    returned: always
    type: string
    sample: hostname.example.com
hw_chassis_type:
    description: Chassis type
    returned: always
    type: string
    sample: Blade, RackMount, etc. pp.
hw_enclosure:
    description: Blade enclosure
    returned: if server is a blade
    type: string
    sample: enclosure abc
hw_bay:
    description: Blade enclosure location
    returned: if server is a blade
    type: string
    sample: Bay 4
hw_rack:
    description: Chassis rack location
    returned: if server is a blade
    type: string
    sample: Rack ABC
hw_ilo_firmware_version:
    description: iLO firmware version (string)
    returned: always
    type: string
    sample: iLO 4 v2.50
hw_ilo_firmware_version_number:
    description: iLO firmware (number)
    returned: always
    type: string
    sample: 250
hw_ilo_firmware_date:
    description: iLO firmware date
    returned: always
    type: string
    sample: Sep 23 2016
hw_ilo_mac_address:
    description: iLO Dedicated Network Port MAC address
    returned: always
    type: dictionary
    sample:
      - macaddress: 00:11:22:33:44:55
        macaddress_dash: 00-11-22-33-44-55
hw_ilo_ipv4_address:
    description: Configured IPv4 address
    returned: always
    type: string
    sample: Sep 23 2016
fhw_ilo_ipv4_subnet_mask:
    description: Configured Subnet Mask
    returned: always
    type: string
    sample: 255.255.255.0
hw_ilo_ipv4_gateway:
    description: Configured Gateway IPv4 Address
    returned: always
    type: string
    sample: 192.168.1.1
hw_ilo_fqdn:
    description: iLO FQDN
    returned: always
    type: string
    sample: hostname-ilo.example.com
'''


def gather_server_facts(module, restobj):
    """Gather server facts"""
    facts = {}

    IsBlade = False

    instances = restobj.search_for_type(module, "ComputerSystem.")
    for instance in instances:
        # instance["href"]: /rest/v1/Systems/1
        system = restobj.rest_get(instance["href"])
        if system.status != 200:
            message = restobj.message_handler(module, system)
            module.fail_json(msg='Return code %s: %s' % (system.status, message))
        facts['hw_bios_version'] = system.dict['Oem']['Hp']['Bios']['Current']['VersionString'].strip()
        facts['hw_bios_date'] = system.dict['Oem']['Hp']['Bios']['Current']['Date'].strip()
        facts['hw_manufacturer'] = system.dict['Manufacturer'].strip()
        facts['hw_model'] = system.dict['Model'].strip()
        facts['hw_processor_model'] = system.dict['ProcessorSummary']['Model'].strip()
        facts['hw_processor_count'] = system.dict['ProcessorSummary']['Count']
        facts['hw_memory'] = system.dict['MemorySummary']['TotalSystemMemoryGiB']
        facts['hw_uuid'] = system.dict['UUID'].strip()
        facts['hw_serial_number'] = system.dict['SerialNumber'].strip()
        facts['hw_sku'] = system.dict['SKU'].strip()
        facts['hw_asset_tag'] = system.dict['AssetTag'].strip()
        facts['hw_power_state'] = system.dict['PowerState'].strip()
        facts['hw_post_state'] = system.dict['Oem']['Hp']['PostState'].strip()
        facts['hw_health'] = system.dict['Status']['Health'].strip()
        # MAC addresses
        for i, mac_address in enumerate(system.dict['HostCorrelation']['HostMACAddress']):
            factname = 'hw_eth' + str(i)
            facts[factname] = {
                'macaddress': mac_address,
                'macaddress_dash': mac_address.replace(':', '-')
            }
        facts['hw_hostname'] = system.dict['HostName'].strip()

    instances = restobj.search_for_type(module, "Chassis.")
    for instance in instances:
        # instance["href"]: /rest/v1/Chassis/1
        chassis = restobj.rest_get(instance["href"])
        if chassis.status != 200:
            message = restobj.message_handler(module, chassis)
            module.fail_json(msg='Return code %s: %s' % (chassis.status, message))
        facts['hw_chassis_type'] = chassis.dict['ChassisType'].strip()
        if chassis.dict['ChassisType'].strip() == "Blade":
            IsBlade = True

    instances = restobj.search_for_type(module, "Manager.")
    for instance in instances:
        # instance["href"]: /rest/v1/Managers/1
        manager = restobj.rest_get(instance["href"])
        if manager.status != 200:
            message = restobj.message_handler(module, manager)
            module.fail_json(msg='Return code %s: %s' % (manager.status, message))
        facts['hw_ilo_firmware_version'] = manager.dict['Oem']['Hp']['Firmware']['Current']['VersionString'].strip()
        facts['hw_ilo_firmware_version_number'] = int(
            str(manager.dict['Oem']['Hp']['Firmware']['Current']['MajorVersion']) +
            str(manager.dict['Oem']['Hp']['Firmware']['Current']['MinorVersion'])
            )    # e.g. 250
        facts['hw_ilo_firmware_date'] = manager.dict['Oem']['Hp']['Firmware']['Current']['Date'].strip()

    instances = restobj.search_for_type(module, "EthernetNetworkInterface.")
    for instance in instances:
        # NIC1: "Dedicated Network Port"
        if instance["href"] == '/rest/v1/Managers/1/EthernetInterfaces/1':
            nic1 = restobj.rest_get(instance["href"])
            facts['hw_ilo_mac_address'] = {
                'macaddress': nic1.dict['MacAddress'],
                'macaddress_dash': nic1.dict['MacAddress'].replace(':', '-')
            }
            facts['hw_ilo_ipv4_address'] = nic1.dict['IPv4Addresses'][0]['Address']
            facts['hw_ilo_ipv4_subnet_mask'] = nic1.dict['IPv4Addresses'][0]['SubnetMask']
            facts['hw_ilo_ipv4_gateway'] = nic1.dict['IPv4Addresses'][0]['Gateway']

    instances = restobj.search_for_type(module, "ManagerNetworkService.")
    for instance in instances:
        # instance["href"]: /rest/v1/Managers/1/NetworkService
        network_service = restobj.rest_get(instance["href"])
        if network_service.status != 200:
            message = restobj.message_handler(module, network_service)
            module.fail_json(msg='Return code %s: %s' % (network_service.status, message))
        facts['hw_ilo_fqdn'] = network_service.dict['FQDN'].strip()

    if IsBlade:
        instances = restobj.search_for_type(module, "ServiceRoot.")
        for instance in instances:
            # instance["href"]: /rest/v1/
            root = restobj.rest_get(instance["href"])
            if root.status != 200:
                message = restobj.message_handler(module, root)
                module.fail_json(msg='Return code %s: %s' % (root.status, message))
            facts['hw_enclosure'] = root.dict['Oem']['Hp']['Manager'][0]['Blade']['EnclosureName'].strip()
            facts['hw_rack'] = root.dict['Oem']['Hp']['Manager'][0]['Blade']['RackName'].strip()
            facts['hw_bay'] = root.dict['Oem']['Hp']['Manager'][0]['Blade']['BayNumber'].strip()

    module.exit_json(ansible_facts=facts)

def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True, type='str'),
            login=dict(default='Administrator', type='str'),
            password=dict(default='admin', type='str', no_log=True)
        ),
        supports_check_mode=True
    )

    ilo_hostname = module.params['host']
    ilo_login = module.params['login']
    ilo_password = module.params['password']

    ilo_url = "https://" + ilo_hostname

    # # Create a REST object
    REST_OBJ = RestObject(module, ilo_url, ilo_login, ilo_password)

    gather_server_facts(module, REST_OBJ)


if __name__ == '__main__':
    main()
