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
module: hpilorest_reset
version_added: "n/a"
author: Christian Kotte (@ckotte)
short_description: Reset HPE iLO interface.
description:
- This module resets an HPE iLO interface.
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
- name: Reset iLO
  hpilorest_reset:
    host: "{{ inventory_hostname }}"
    login: "{{ hpilo_login }}"
    password: "{{ hpilo_password }}"
  delegate_to: 127.0.0.1
'''

RETURN = '''
# Default return values
'''


def reset_ilo(module, restobj):
    """reset iLO"""
    instances = restobj.search_for_type(module, "Manager.")
    for instance in instances:
        body = {"Action": "Reset"}
        response = restobj.rest_post(instance["href"], body)
        message = restobj.message_handler(module, response)
        if response.status == 200:
            module.exit_json(changed=True, msg="iLO reset: %s" % message)
        else:
            module.fail_json(msg='Return code %s: %s' % (response.status, message))


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True, type='str'),
            login=dict(default='Administrator', type='str'),
            password=dict(default='admin', type='str', no_log=True)
        ),
    )

    ilo_hostname = module.params['host']
    ilo_login = module.params['login']
    ilo_password = module.params['password']

    ilo_url = "https://" + ilo_hostname

    # # Create a REST object
    REST_OBJ = RestObject(module, ilo_url, ilo_login, ilo_password)

    reset_ilo(module, REST_OBJ)


if __name__ == '__main__':
    main()
