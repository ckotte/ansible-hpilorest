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
module: hpilorest_mount_iso
version_added: "n/a"
author: Christian Kotte (@ckotte)
short_description: Mount ISO via an HPE iLO interface.
description:
- This module mounts an ISO through an HPE iLO interface.
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
  iso_url:
    description:
    - xxx.
  state:
    description:
    - Wheter the ISO should be mounted.
requirements:
- python-ilorest-library
- python >= 2.7.9
notes:
- This module ought to be run from a system that can access the HPE iLO
  interface directly, either by using C(local_action) or using C(delegate_to).
'''

EXAMPLES = r'''
- name: Mount ISO
  hpilorest_mount_iso:
    host: "{{ inventory_hostname }}"
    login: "{{ hpilo_login }}"
    password: "{{ hpilo_password }}"
    iso_url: http://10.145.91.134/pxeboot/esxi/images/HPE-FW/881936_001_spp-2017.07.1-SPP2017071.2017_0718.11.iso
  delegate_to: localhost
'''

RETURN = '''
# Default return values
'''


def mount_iso(module, restobj, iso_url, boot_on_next_server_reset, state, bios_password=None):
    """Mount ISO"""
    instances = restobj.search_for_type(module, "Manager.")

    for instance in instances:
        # instance["href"]: /rest/v1/Managers/1
        manager = restobj.rest_get(instance["href"])
        # manager.dict[...]: /rest/v1/Managers/1/VirtualMedia
        virtual_media = restobj.rest_get(manager.dict["links"]["VirtualMedia"]["href"])
        # vmlink: /rest/v1/Managers/1/VirtualMedia/1 ("MediaTypes": ["Floppy","USBStick"])
        # vmlink: /rest/v1/Managers/1/VirtualMedia/2 ("MediaTypes": ["CD","DVD"])
        for vmlink in virtual_media.dict["links"]["Member"]:
            instance = restobj.rest_get(vmlink["href"])
            message = restobj.message_handler(module, instance)
            if "DVD" in instance.dict["MediaTypes"]:
                if state == 'present':
                    if instance.dict["Image"] == iso_url:
                        changed_status = False
                        message = "ISO already mounted"
                    else:
                        body = {"Image": iso_url}
                        body["Oem"] = {"Hp": {"BootOnNextServerReset": boot_on_next_server_reset}}
                        response = restobj.rest_patch(vmlink["href"], body, optionalpassword=bios_password)
                        message = restobj.message_handler(module, response)
                        if response.status == 200:
                            changed_status = True
                            message = "ISO successfully mounted: %s" % message
                        else:
                            module.fail_json(msg='Return code %s: %s' % (response.status, message))
                    module.exit_json(changed=changed_status, msg=message)
                else:
                    if instance.dict["Image"]:
                        body = {"Action": "EjectVirtualMedia", "Target": "/Oem/Hp"}
                        response = restobj.rest_patch(vmlink["href"], body, optionalpassword=bios_password)
                        message = restobj.message_handler(module, response)
                        if response.status == 200:
                            changed_status = True
                            message = "ISO successfully ejected: %s" % message
                        else:
                            module.fail_json(msg='Return code %s: %s' % (response.status, message))
                    else:
                        changed_status = False
                        message = "No ISO mounted"
                    module.exit_json(changed=changed_status, msg=message)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True, type='str'),
            login=dict(default='Administrator', type='str'),
            password=dict(default='admin', type='str', no_log=True),
            iso_url=dict(required=True, type='str'),
            boot_on_next_server_reset=dict(default=True, type='bool'),
            state=dict(default='present', choices=['present', 'absent'])
        ),
    )

    ilo_hostname = module.params['host']
    ilo_login = module.params['login']
    ilo_password = module.params['password']
    iso_url = module.params['iso_url']
    boot_on_next_server_reset = module.params['boot_on_next_server_reset']
    state = module.params['state']

    ilo_url = "https://" + ilo_hostname

    # # Create a REST object
    REST_OBJ = RestObject(module, ilo_url, ilo_login, ilo_password)

    mount_iso(module, REST_OBJ, iso_url, boot_on_next_server_reset, state)


if __name__ == '__main__':
    main()
