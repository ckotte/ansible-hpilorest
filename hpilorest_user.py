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
module: hpilorest_user
version_added: "n/a"
author: Christian Kotte (@ckotte)
short_description: Configure user in HPE iLO.
description:
- This module configures user accounts in HPE iLO.
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
  login_name:
    description:
    - The user's login name.
  user_name:
    description:
    - The user's user name.
  user_password:
    description:
    - The user's password.
  update_password:
    description:
    - Whether to update the user's password.
  irc:
    description:
    - Wheter to grant Integrated Remote Console priviledge.
    choices: [ "yes", "no" ]
  cfg:
    description:
    - Wheter to grant Configure iLO Settings priviledge.
    choices: [ "yes", "no" ]
  virtual_media:
    description:
    - Wheter to grant Virtual Media priviledge.
    choices: [ "yes", "no" ]
  usercfg:
    description:
    - Wheter to grant Administer User Accounts priviledge.
    choices: [ "yes", "no" ]
  vpr:
    description:
    - Wheter to grant Integrated Remote Console priviledge.
    choices: [ "yes", "no" ]
requirements:
- python-ilorest-library
- python >= 2.7.9
notes:
- This module ought to be run from a system that can access the HPE iLO
  interface directly, either by using C(local_action) or using C(delegate_to).
'''

EXAMPLES = r'''
- name: iLO | Configure user account
  tags: user
  hpilorest_user:
    host: "{{ inventory_hostname }}"
    login: "{{ hpilo_login }}"
    password: "{{ hpilo_password }}"
    login_name: "{{ hpilo_new_user }}"
    user_name: "{{ hpilo_new_user }}"
    user_password: "{{ hpilo_new_password }}"
    irc: "true"
    cfg: "true"
    virtual_media: "true"
    usercfg: "true"
    vpr: "true"
  delegate_to: 127.0.0.1
'''

RETURN = '''
# Default return values
'''


def configure_user_account(module, restobj, new_iLO_loginname, new_iLO_username, new_iLO_password, update_password, irc, cfg, virtual_media, usercfg,
                           vpr, state, bios_password=None):
    """Create or configure an iLO User Account"""
    instances = restobj.search_for_type(module, "AccountService.")

    changed = []

    for instance in instances:
        accounts_href = restobj.rest_get(instance["href"])
        accounts = restobj.rest_get(accounts_href.dict["links"]["Accounts"]["href"])

        account_found = False
        account_changed = False
        for account in accounts.dict["Items"]:
            if account["UserName"] == new_iLO_loginname:
                account_found = True
                # Modify account
                if state == 'present':
                    body = {}
                    body_oemhp = {}
                    body_oemhp_privs = {}

                    # update password if update_password is True
                    if update_password:
                        body["Password"] = new_iLO_password
                        changed.append('Password')
                        account_changed = True

                    # update login name if different
                    if account['Oem']['Hp']['LoginName'] != new_iLO_loginname:
                        body_oemhp["LoginName"] = new_iLO_username
                        changed.append('LoginName')
                        account_changed = True

                    # update priviledges if different
                    if account['Oem']['Hp']['Privileges']['RemoteConsolePriv'] != irc:
                        body_oemhp_privs["RemoteConsolePriv"] = irc
                        changed.append('RemoteConsolePriv')
                        account_changed = True
                    if account['Oem']['Hp']['Privileges']['iLOConfigPriv'] != cfg:
                        body_oemhp_privs["iLOConfigPriv"] = cfg
                        changed.append('iLOConfigPriv')
                        account_changed = True
                    if account['Oem']['Hp']['Privileges']['VirtualMediaPriv'] != virtual_media:
                        body_oemhp_privs["VirtualMediaPriv"] = virtual_media
                        changed.append('VirtualMediaPriv')
                        account_changed = True
                    if account['Oem']['Hp']['Privileges']['UserConfigPriv'] != usercfg:
                        body_oemhp_privs["UserConfigPriv"] = usercfg
                        changed.append('UserConfigPriv')
                        account_changed = True
                    if account['Oem']['Hp']['Privileges']['VirtualPowerAndResetPriv'] != vpr:
                        body_oemhp_privs["VirtualPowerAndResetPriv"] = vpr
                        changed.append('VirtualPowerAndResetPriv')
                        account_changed = True

                    # component assembly
                    if account_changed:
                        if module.check_mode:
                            changed_status = True
                        else:
                            if len(body_oemhp_privs):
                                body_oemhp["Privileges"] = body_oemhp_privs
                            if len(body_oemhp):
                                body["Oem"] = {"Hp": body_oemhp}

                            response = restobj.rest_patch(account["links"]["self"]["href"], body, optionalpassword=bios_password)
                            message = restobj.message_handler(module, response)
                            if response.status == 200:
                                changed_status = True
                            else:
                                module.fail_json(msg="Return code %s: %s" % (response.status, message))
                    else:
                        changed_status = False
                        message = 'User %s not changed' % new_iLO_loginname

                    if changed_status:
                        if module.check_mode:
                            changed_message = ' would be changed.'
                        else:
                            changed_message = ' changed.'
                        if len(changed) > 2:
                            message = ', '.join(changed[:-1]) + ', and ' + str(changed[-1]) + changed_message
                        elif len(changed) == 2:
                            message = ' and '.join(changed) + changed_message
                        elif len(changed) == 1:
                            message = changed[0] + changed_message
                        message = ('User %s already created, but ' + message) % new_iLO_loginname
                    else:
                        message = 'User %s already created an all settings are already configured' % new_iLO_loginname

                    module.exit_json(changed=changed_status, msg=message)
                # Delete account
                else:
                    if module.check_mode:
                        module.exit_json(changed=True, msg='User %s would be deleted.' % new_iLO_loginname)
                    else:
                        response = restobj.rest_delete(account["links"]["self"]["href"])
                        message = restobj.message_handler(module, response)
                        if response.status == 200:
                            module.exit_json(changed=True, msg='User %s deleted.' % new_iLO_loginname)
                        else:
                            module.fail_json(msg="Return code %s: %s" % (response.status, message))

        if not account_found:
            # Create new account
            if state == 'present':
                if module.check_mode:
                    changed_status = True
                    message = 'User %s would be created' % new_iLO_loginname
                else:
                    body = {'UserName': new_iLO_loginname, 'Password': new_iLO_password, 'Oem': {}}
                    body['Oem']['Hp'] = {}
                    body['Oem']['Hp']['LoginName'] = new_iLO_username
                    body['Oem']['Hp']['Privileges'] = {}
                    body['Oem']['Hp']['Privileges']['RemoteConsolePriv'] = irc
                    body['Oem']['Hp']['Privileges']['iLOConfigPriv'] = cfg
                    body['Oem']['Hp']['Privileges']['VirtualMediaPriv'] = virtual_media
                    body['Oem']['Hp']['Privileges']['UserConfigPriv'] = usercfg
                    body['Oem']['Hp']['Privileges']['VirtualPowerAndResetPriv'] = vpr
                    response = restobj.rest_post(accounts_href.dict["links"]["Accounts"]["href"], body)
                    message = restobj.message_handler(module, response)
                    if response.status == 201:
                        changed_status = True
                        message = 'User %s created' % new_iLO_loginname
                    else:
                        module.fail_json(msg="Return code %s: %s" % (response.status, message))
                    module.exit_json(changed=changed_status, msg=message)
            # Do nothing
            else:
                module.exit_json(changed=False, msg='User %s not present' % new_iLO_loginname)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True, type='str'),
            login=dict(default='Administrator', type='str'),
            password=dict(default='admin', type='str', no_log=True),
            login_name=dict(required=True, type='str'),
            user_name=dict(required=True, type='str'),
            user_password=dict(required=True, type='str', no_log=True),
            update_password=dict(required=False, type='bool'),
            irc=dict(required=True, type='bool'),
            cfg=dict(required=True, type='bool'),
            virtual_media=dict(required=True, type='bool'),
            usercfg=dict(required=True, type='bool'),
            vpr=dict(required=True, type='bool'),
            state=dict(default='present', choices=['present', 'absent'])
        ),
        supports_check_mode=True
    )

    ilo_hostname = module.params['host']
    ilo_login = module.params['login']
    ilo_password = module.params['password']
    login_name = module.params['login_name']
    user_name = module.params['user_name']
    user_password = module.params['user_password']
    update_password = module.params['update_password']
    irc = module.params['irc']                      # Integrated Remote Console
    cfg = module.params['cfg']                      # Configure iLO Settings
    virtual_media = module.params['virtual_media']  # Virtual Media
    usercfg = module.params['usercfg']              # Administer User Accounts
    vpr = module.params['vpr']                      # Virtual Power and Reset
    state = module.params['state']

    ilo_url = "https://" + ilo_hostname

    # Create a REST object
    REST_OBJ = RestObject(module, ilo_url, ilo_login, ilo_password)

    configure_user_account(module, REST_OBJ, login_name, user_name, user_password, update_password, irc, cfg, virtual_media, usercfg, vpr, state)


if __name__ == '__main__':
    main()
