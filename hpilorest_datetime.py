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
module: hpilorest_datetime
version_added: "n/a"
author: Christian Kotte (@ckotte)
short_description: Set HPE iLO time zone and NTP.
description:
- This module sets HPE iLO time zone and NTP.
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
  timezone:
    description:
    - The time zone to be configured.
    required: true
  ntp_server_1:
    description:
    - The first NTP server IP or address to be configured.
    required: true
  ntp_server_2:
    description:
    - The second NTP server IP or address to be configured.
    required: true
requirements:
- python-ilorest-library
- python >= 2.7.9
notes:
- This module ought to be run from a system that can access the HPE iLO
  interface directly, either by using C(local_action) or using C(delegate_to).
'''

EXAMPLES = r'''
- name: iLO | Configure time
  tags: time
  hpilorest_datetime:
    host: "{{ inventory_hostname }}"
    login: "{{ hpilo_login }}"
    password: "{{ hpilo_password }}"
    timezone: "{{ timezone }}"
    ntp_server_1: "{{ ntp_servers[0] }}"
    ntp_server_2: "{{ ntp_servers[1] }}"
  delegate_to: 127.0.0.1
'''

RETURN = '''
# Default return values
'''


def check_datetime(module, restobj, timezone, ntp_server_1, ntp_server_2, bios_password=None):
    """Inform the user what would change if the module were run"""

    would_be_changed = []
    pending_reset = False
    changed_status = False

    instances = restobj.search_for_type(module, "HpiLODateTime.")
    for instance in instances:
        # instance["href"]: /rest/v1/Managers/1/DateTime
        date_time = restobj.rest_get(instance["href"])
        # Time zone
        if date_time.dict['TimeZone']['Name'] == timezone:
            if date_time.dict['ConfigurationSettings'] == 'SomePendingReset':
                pending_reset = True
        else:
            would_be_changed.append('TimeZone')
            changed_status = True
        # NTP servers
        if ((date_time.dict['NTPServers'][0] == ntp_server_1) and (date_time.dict['NTPServers'][1] == ntp_server_2)):
            if date_time.dict['ConfigurationSettings'] == 'SomePendingReset':
                pending_reset = True
        else:
            would_be_changed.append('NTPServers')
            changed_status = True

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


def set_datetime(module, restobj, timezone, ntp_server_1, ntp_server_2, bios_password=None):
    """Set Network Service setting"""

    changed = []
    pending_reset = False
    changed_status = False

    instances = restobj.search_for_type(module, "HpiLODateTime.")
    for instance in instances:
        # instance["href"]: /rest/v1/Managers/1/DateTime
        date_time = restobj.rest_get(instance["href"])
        # Time zone
        if date_time.dict['TimeZone']['Name'] == timezone:
            if date_time.dict['ConfigurationSettings'] == 'SomePendingReset':
                pending_reset = True
        else:
            # loop through predefined timezone list and find corresponding index
            for tz in date_time.dict["TimeZoneList"]:
                if tz["Name"].startswith(timezone):
                    body = {"TimeZone": {"Index": tz["Index"]}}
                    response = restobj.rest_patch(instance["href"], body, optionalpassword=bios_password)
                    message = restobj.message_handler(module, response)
                    if response.status == 200:
                        changed_status = True
                        changed.append('TimeZone')
                    else:
                        module.fail_json(msg="Return code %s: %s" % (response.status, message))
        # NTP servers
        if ((date_time.dict['NTPServers'][0] == ntp_server_1) and (date_time.dict['NTPServers'][1] == ntp_server_2)):
            if date_time.dict['ConfigurationSettings'] == 'SomePendingReset':
                pending_reset = True
        else:
            body = {"StaticNTPServers": [ntp_server_1, ntp_server_2]}
            response = restobj.rest_patch(instance["href"], body, optionalpassword=bios_password)
            message = restobj.message_handler(module, response)
            if response.status == 200:
                changed_status = True
                changed.append('NTPServers')
            else:
                module.fail_json(msg="Return code %s: %s" % (response.status, message))

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
            timezone=dict(required=True, type='str'),
            ntp_server_1=dict(required=True, type='str'),
            ntp_server_2=dict(required=True, type='str')
        ),
        supports_check_mode=True
    )

    ilo_hostname = module.params['host']
    ilo_login = module.params['login']
    ilo_password = module.params['password']
    timezone = module.params['timezone']
    ntp_server_1 = module.params['ntp_server_1']
    ntp_server_2 = module.params['ntp_server_2']

    ilo_url = "https://" + ilo_hostname

    # # Create a REST object
    REST_OBJ = RestObject(module, ilo_url, ilo_login, ilo_password)

    if module.check_mode:
        check_datetime(module, REST_OBJ, timezone, ntp_server_1, ntp_server_2)

    set_datetime(module, REST_OBJ, timezone, ntp_server_1, ntp_server_2)


if __name__ == '__main__':
    main()
