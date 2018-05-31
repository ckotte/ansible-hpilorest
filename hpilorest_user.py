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


def check_user_account(module, restobj, new_iLO_loginname, new_iLO_username, new_iLO_password, update_password, irc, cfg, virtual_media, usercfg, vpr, state, bios_password=None):
    """Inform the user what would change if the module were run"""

    would_be_changed = []

    instances = restobj.search_for_type(module, "AccountService.")

    for instance in instances:
        response = restobj.rest_get(instance["href"])
        accounts = restobj.rest_get(response.dict["links"]["Accounts"]["href"])

        account_found = False
        account_changed = False
        for account in accounts.dict["Items"]:
            if account["UserName"] == new_iLO_loginname:
                account_found = True
                if account['Oem']['Hp']['LoginName'] != new_iLO_loginname:
                    would_be_changed.append('LoginName')
                    account_changed = True
                if account['Oem']['Hp']['Privileges']['RemoteConsolePriv'] != irc:
                    would_be_changed.append('RemoteConsolePriv')
                    account_changed = True
                if account['Oem']['Hp']['Privileges']['iLOConfigPriv'] != cfg:
                    would_be_changed.append('iLOConfigPriv')
                    account_changed = True
                if account['Oem']['Hp']['Privileges']['VirtualMediaPriv'] != virtual_media:
                    would_be_changed.append('VirtualMediaPriv')
                    account_changed = True
                if account['Oem']['Hp']['Privileges']['UserConfigPriv'] != usercfg:
                    would_be_changed.append('UserConfigPriv')
                    account_changed = True
                if account['Oem']['Hp']['Privileges']['VirtualPowerAndResetPriv'] != vpr:
                    would_be_changed.append('VirtualPowerAndResetPriv')
                    account_changed = True

        if account_found:
            if account_changed:
                changed_status = False
                message = 'User %s already created, but ' % new_iLO_loginname
                if len(would_be_changed) > 2:
                    message = message + ', '.join(would_be_changed[:-1]) + ', and ' + str(would_be_changed[-1]) + ' would be changed'
                elif len(would_be_changed) == 2:
                    message = message + ' and '.join(would_be_changed) + ' would be changed'
                elif len(would_be_changed) == 1:
                    message = message + would_be_changed[0] + ' would be changed'
            else:
                changed_status = False
                message = 'User %s already created' % new_iLO_loginname
        else:
            changed_status = True
            message = 'User %s would be created' % new_iLO_loginname

        module.exit_json(changed=changed_status, msg=message)


def configure_user_account(module, restobj, new_iLO_loginname, new_iLO_username, new_iLO_password, update_password, irc, cfg, virtual_media, usercfg, vpr, state, bios_password=None):
    """Create or configure an iLO User Account"""
    instances = restobj.search_for_type(module, "AccountService.")

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
                        account_changed = True

                    # update login name if different
                    if account['Oem']['Hp']['LoginName'] != new_iLO_loginname:
                        body_oemhp["LoginName"] = new_iLO_username
                        account_changed = True

                    # update priviledges if different
                    if account['Oem']['Hp']['Privileges']['RemoteConsolePriv'] != irc:
                        body_oemhp_privs["RemoteConsolePriv"] = irc
                        account_changed = True
                    if account['Oem']['Hp']['Privileges']['iLOConfigPriv'] != cfg:
                        body_oemhp_privs["iLOConfigPriv"] = cfg
                        account_changed = True
                    if account['Oem']['Hp']['Privileges']['VirtualMediaPriv'] != virtual_media:
                        body_oemhp_privs["VirtualMediaPriv"] = virtual_media
                        account_changed = True
                    if account['Oem']['Hp']['Privileges']['UserConfigPriv'] != usercfg:
                        body_oemhp_privs["UserConfigPriv"] = usercfg
                        account_changed = True
                    if account['Oem']['Hp']['Privileges']['VirtualPowerAndResetPriv'] != vpr:
                        body_oemhp_privs["VirtualPowerAndResetPriv"] = vpr
                        account_changed = True

                    # component assembly
                    if account_changed:
                        if len(body_oemhp_privs):
                            body_oemhp["Privileges"] = body_oemhp_privs
                        if len(body_oemhp):
                            body["Oem"] = {"Hp": body_oemhp}

                        response = restobj.rest_patch(account["links"]["self"]["href"], body, optionalpassword=bios_password)
                        message = restobj.message_handler(module, response)
                        if response.status == 200:
                            changed_status = True
                            message = 'User %s modified: %s' % (new_iLO_loginname, message)
                        else:
                            module.fail_json(msg="Return code %s: %s" % (response.status, message))
                    else:
                        changed_status = False
                        message = 'User %s not changed' % new_iLO_loginname

                    module.exit_json(changed=changed_status, msg=message)
                # Delete account
                else:
                    response = restobj.rest_delete(account["links"]["self"]["href"])
                    message = restobj.message_handler(module, response)
                    if response.status == 200:
                        module.exit_json(changed=True, msg='User %s deleted: %s' % (new_iLO_loginname, message))
                    else:
                        module.fail_json(msg="Return code %s: %s" % (response.status, message))

        if not account_found:
            # Create new account
            if state == 'present':
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
                    module.exit_json(changed=True, msg='User created: %s' % message)
                else:
                    module.fail_json(msg="Return code %s: %s" % (response.status, message))
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

    if module.check_mode:
        check_user_account(module, REST_OBJ, login_name, user_name, user_password, update_password, irc, cfg, virtual_media, usercfg, vpr, state)

    configure_user_account(module, REST_OBJ, login_name, user_name, user_password, update_password, irc, cfg, virtual_media, usercfg, vpr, state)


if __name__ == '__main__':
    main()
