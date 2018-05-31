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
module: hpilorest_bios
version_added: "n/a"
author: Christian Kotte (@ckotte)
short_description: Set BIOS values through an HPE iLO interface
description:
- This module sets BIOS values for a specific system using its HPE iLO interface.
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
  bios_property:
    description:
    - The BIOS property to be configured.
  property_value:
    description:
    - The BIOS property value to be configured.
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
  bios_property: "BootMode"
  # "Uefi": UEFI Mode
  # "LegacyBios": Legacy BIOS Mode
  property_value: "LegacyBios"
delegate_to: 127.0.0.1
'''

RETURN = '''
# Default return values
'''


def check_bios_setting(module, restobj, bios_property, property_value, bios_password=None):
    """Inform the user what would change if the module were run"""

    changed_status = False

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
        if bios_pending.dict[bios_property] == property_value:
            message = "%s already set" % bios_property
        else:
            changed_status = True
            message = "%s would be changed" % bios_property
        # check BIOS setting (current)
        if bios_current.dict[bios_property] != property_value:
            changed_status = True
            message = message + ' (server reboot required)'

    module.exit_json(changed=changed_status, msg=message)


def set_bios_setting(module, restobj, bios_property, property_value, bios_password=None):
    """Set BIOS setting"""

    changed_status = False

    bios_current = restobj.rest_get("/rest/v1/systems/1/bios")
    message = restobj.message_handler(module, bios_current)
    if bios_current.status != 200:
        module.fail_json(msg='Return code %s: %s' % (bios_current.status, message))

    instances = restobj.search_for_type(module, "Bios.")
    for instance in instances:
        # set BIOS setting (pending)
        # instance["href"]: /rest/v1/Systems/1/Bios/Settings
        bios_pending = restobj.rest_get(instance["href"])
        message = restobj.message_handler(module, bios_current)
        if bios_current.status != 200:
            module.fail_json(msg='Return code %s: %s' % (bios_current.status, message))
        if bios_pending.dict[bios_property] == property_value:
            message = "%s already configured" % bios_property
        else:
            body = {bios_property: property_value}
            response = restobj.rest_patch(instance["href"], body, optionalpassword=bios_password)
            message = restobj.message_handler(module, response)
            if response.status == 200:
                changed_status = True
                message = "%s changed: %s" % (bios_property, message)
            else:
                module.fail_json(msg='Return code %s: %s' % (response.status, message))
        # check BIOS setting (current)
        if bios_current.dict[bios_property] != property_value:
            changed_status = True
            message = message + ' (server reboot required)'

        module.exit_json(changed=changed_status, msg=message)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True, type='str'),
            login=dict(default='Administrator', type='str'),
            password=dict(default='admin', type='str', no_log=True),
            bios_property=dict(required=True, type='str'),
            property_value=dict(required=True, type='str')
        ),
        supports_check_mode=True
    )

    ilo_hostname = module.params['host']
    ilo_login = module.params['login']
    ilo_password = module.params['password']
    change_property = module.params['bios_property']
    change_value = module.params['property_value']

    ilo_url = "https://" + ilo_hostname

    # # Create a REST object
    REST_OBJ = RestObject(module, ilo_url, ilo_login, ilo_password)

    if module.check_mode:
        check_bios_setting(module, REST_OBJ, change_property, change_value)

    set_bios_setting(module, REST_OBJ, change_property, change_value)


if __name__ == '__main__':
    main()
