#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2018 Christian Kotte <christian.kotte@gmx.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import sys
try:
    import json
except ImportError:
    import simplejson as json

from ansible.module_utils.basic import AnsibleModule

try:
    from redfish import AuthMethod, rest_client
    HAS_HPE_ILOREST = True
except ImportError:
    HAS_HPE_ILOREST = False


class RestObject(object):
    def __init__(self, module, host, login_account, login_password):
        self.check_hpe_ilorest(module)
        self.rest_client = rest_client(base_url=host,
                                       username=login_account, password=login_password,
                                       default_prefix="/rest/v1")
        self.rest_client.login(auth=AuthMethod.SESSION)
        self.SYSTEMS_RESOURCES = self.get_resource_directory(module)
        self.MESSAGE_REGISTRIES = self.get_base_registry(module)

    def check_hpe_ilorest(self, module):
        if not HAS_HPE_ILOREST:
            module.fail_json(msg="python-ilorest-library is required")

    def __del__(self):
        self.rest_client.logout()

    def search_for_type(self, module, type):
        """Search for type in resource directory"""
        instances = []

        for item in self.SYSTEMS_RESOURCES["resources"]:
            foundsettings = False

            if type and type.lower() in item["Type"].lower():
                for entry in self.SYSTEMS_RESOURCES["resources"]:
                    if (item["href"] + "/settings").lower() == (entry["href"]).lower():
                        foundsettings = True

                if not foundsettings:
                    instances.append(item)

        if not instances:
            module.fail_json(msg="'%s' resource or feature is not supported on this system" % type)

        return instances

    def message_handler(self, module, response):
        """Return iLO return message"""
        if not self.MESSAGE_REGISTRIES:
            module.fail_json(msg="No message registries found")

        try:
            message = json.loads(response.text)
            newmessage = message["Messages"][0]["MessageID"].split(".")
        except:
            return "No extended information returned by iLO."

        for err_mesg in self.MESSAGE_REGISTRIES:
            if err_mesg != newmessage[0]:
                continue
            else:
                for err_entry in self.MESSAGE_REGISTRIES[err_mesg]:
                    if err_entry == newmessage[3]:
                        # iLO return code: message["Messages"][0]["MessageID"],
                        return self.MESSAGE_REGISTRIES[err_mesg][err_entry]["Description"]

    def rest_get(self, suburi):
        """REST GET"""
        return self.rest_client.get(path=suburi)

    def rest_patch(self, suburi, request_body, optionalpassword=None):
        """REST PATCH"""
        return self.rest_client.patch(path=suburi, body=request_body,
                                          optionalpassword=optionalpassword)

    def rest_put(self, suburi, request_body, optionalpassword=None):
        """REST PUT"""
        return self.rest_client.put(path=suburi, body=request_body,
                                        optionalpassword=optionalpassword)

    def rest_post(self, suburi, request_body):
        """REST POST"""
        return self.rest_client.post(path=suburi, body=request_body)

    def rest_delete(self, suburi):
        """REST DELETE"""
        return self.rest_client.delete(path=suburi)

    def get_resource_directory(self, module):
        """Get resource directory instances"""
        response = self.rest_get("/rest/v1/resourcedirectory")
        resources = {}

        if response.status == 200:
            resources["resources"] = response.dict["Instances"]
            return resources
        else:
            module.fail_json(msg="Resource directory missing at /rest/v1/resourcedirectory")

    def get_base_registry(self, module):
        """Get messages from registry"""
        response = self.rest_get("/rest/v1/Registries")
        messages = {}

        identifier = None

        for entry in response.dict["Items"]:
            if "Id" in entry:
                identifier = entry["Id"]
            else:
                identifier = entry["Schema"].split(".")[0]

            if identifier not in ["Base", "iLO"]:
                continue

            for location in entry["Location"]:
                reg_resp = self.rest_get(location["Uri"]["extref"])

                if reg_resp.status == 200:
                    messages[identifier] = reg_resp.dict["Messages"]
                else:
                    module.fail_json(msg=identifier + " not found at " + location["Uri"]["extref"])

        return messages
