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
module: hpilorest_bios_facts
version_added: "n/a"
author: Christian Kotte (@ckotte) <christian.kotte@gmx.de>
short_description: Get BIOS values through an HPE iLO interface
description:
- This module can be used to gather facts about BIOS values for a specific system using its HPE iLO interface.
- One dictionary contains the Platform/BIOS Configuration (RBSU) Current Settings
- One dictionary contains the Platform/BIOS Configuration (RBSU) Pending Settings
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
- name: BIOS | Enable LegacyBIOS
hpilorest_bios:
  host: "{{ inventory_hostname }}"
  login: "{{ hpilo_login }}"
  password: "{{ hpilo_password }}"
delegate_to: 127.0.0.1
'''

RETURN = r'''
bios_facts:
    description:
    - dict with current_settings and pending_settings as key and dict with BIOS config facts
    returned: always
    type: dict
    bios_facts: {
        "current_settings": {
            "AcpiRootBridgePxm": "Enabled",
            "AcpiSlit": "Enabled",
            "AdjSecPrefetch": "Enabled",
            "AdminEmail": "",
            "AdminName": "",
            "AdminOtherInfo": ""
        }
        "pending_settings": {
            "AcpiRootBridgePxm": "Enabled",
            "AcpiSlit": "Enabled",
            "AdjSecPrefetch": "Enabled",
            "AdminEmail": "",
            "AdminName": "",
            "AdminOtherInfo": ""
        }
    }
'''


def get_bios_settings(module, restobj, bios_password=None):
    """Get BIOS settings"""

    bios_current = restobj.rest_get("/rest/v1/systems/1/bios")
    message = restobj.message_handler(module, bios_current)
    if bios_current.status != 200:
        module.fail_json(msg='Return code %s: %s' % (bios_current.status, message))

    instances = restobj.search_for_type(module, "Bios.")
    for instance in instances:
        # check BIOS setting (pending)
        # instance["href"]: /rest/v1/Systems/1/Bios/Settings
        bios_pending = restobj.rest_get(instance["href"])
        message = restobj.message_handler(module, bios_current)
        if bios_current.status != 200:
            module.fail_json(msg='Return code %s: %s' % (bios_current.status, message))

    bios_facts = {}
    bios_current_facts = {}
    bios_pending_facts = {}

    for key, value in bios_current.dict.items():
        # Don't include "useless" keys
        if key not in ("links", "Description", "SettingsResult"):
            bios_current_facts[key] = value

    for key, value in bios_pending.dict.items():
        # Don't include "useless" keys
        if key not in ("links", "Description"):
            bios_pending_facts[key] = value

    bios_facts["current_settings"] = bios_current_facts
    bios_facts["pending_settings"] = bios_pending_facts

    module.exit_json(changed=False, bios_facts=bios_facts)


def main():
    """Main"""
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

    get_bios_settings(module, REST_OBJ)


if __name__ == '__main__':
    main()
