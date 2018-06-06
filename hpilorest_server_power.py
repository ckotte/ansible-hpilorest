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
module: hpilorest_server_power
version_added: "n/a"
author: Christian Kotte (@ckotte)
short_description: Configure server power state through an HPE iLO interface.
description:
- This module reboots or shuts down a server through an HPE iLO interface.
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
  action:
    description:
    - The server power action.
    default=ForceSystemReset
    choices=['GracefulPowerOff', 'ForcePowerOff', 'ForceSystemReset', 'ColdBoot']
requirements:
- python-ilorest-library
- python >= 2.7.9
notes:
- This module ought to be run from a system that can access the HPE iLO
  interface directly, either by using C(local_action) or using C(delegate_to).
'''

EXAMPLES = r'''
- name: Restart Server
  hpilorest_server_power:
    host: "{{ inventory_hostname }}"
    login: "{{ hpilo_login }}"
    password: "{{ hpilo_password }}"
    action: "ForceSystemReset"
  delegate_to: 127.0.0.1
'''

RETURN = '''
# Default return values
'''


def server_power(module, restobj, action, bios_password=None):
    """Reset server"""
    instances = restobj.search_for_type(module, "ComputerSystem.")
    for instance in instances:
        # instance["href"]: /rest/v1/Systems/1
        system = restobj.rest_get(instance["href"])
        # Oem.Hp.PostState can contain one of the following values:
        # ""
        # "Unknown"
        # "Reset"
        # "PowerOff"
        # "InPost"
        # "InPostDiscoveryComplete"
        # "FinishedPost"
        if system.dict['Oem']['Hp']['PostState'] == 'FinishedPost':
            # Graceful Power Off: Momentary Press
            if action == 'GracefulPowerOff':
                body = dict()
                body["Action"] = "PowerButton"
                body["PushType"] = "Press"
            # Force Power Off: Press and Hold
            elif action == 'ForcePowerOff':
                body = dict()
                body["Action"] = "PowerButton"
                body["PushType"] = "PressAndHold"
            # Force System Reset: Reset
            elif action == 'ForceSystemReset':
                body = dict()
                body["Action"] = "Reset"
                # "ResetType" must be one of the following value(s):
                # "On"
                # "ForceOff"
                # "ForceRestart"
                # "Nmi"
                # "PushPowerButton"
                body["ResetType"] = "ForceRestart"
            # Force Power Cycle: Cold Boot
            elif action == 'ColdBoot':
                body = dict()
                body["Action"] = "SystemReset"
                body["ResetType"] = "ColdBoot"
            response = restobj.rest_post(instance["href"], body)
            message = restobj.message_handler(module, response)
            if response.status == 200:
                module.exit_json(changed=True, msg="Server power state changed: %s" % message)
            else:
                module.fail_json(msg='Return code %s: %s' % (response.status, message))
        else:
            module.fail_json(msg='Server POST is pending. System Post state: %s'
                             % system.dict['Oem']['Hp']['PostState'])


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True, type='str'),
            login=dict(default='Administrator', type='str'),
            password=dict(default='admin', type='str', no_log=True),
            action=dict(default='ForceSystemReset', choices=['GracefulPowerOff', 'ForcePowerOff', 'ForceSystemReset', 'ColdBoot'])
        ),
        supports_check_mode=True
    )

    ilo_hostname = module.params['host']
    ilo_login = module.params['login']
    ilo_password = module.params['password']
    action = module.params['action']

    ilo_url = "https://" + ilo_hostname

    # # Create a REST object
    REST_OBJ = RestObject(module, ilo_url, ilo_login, ilo_password)

    if module.check_mode:
        module.exit_json(changed=True, msg="Server power state would be changed (" + action + ")")

    server_power(module, REST_OBJ, action)


if __name__ == '__main__':
    main()
