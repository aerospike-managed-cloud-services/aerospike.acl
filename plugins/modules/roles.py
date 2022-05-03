#!/usr/bin/env python3
#!/usr/bin/python

# Copyright: (c) 2018, Terry Jones <terry.jones@example.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import subprocess
import json
from subprocess import run
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.aerospike.acl.plugins.module_utils.acl_common import ACL


class ManageRoles(ACL):
    def __init__(self, host, port, auth_user, auth_password) -> None:
        super().__init__(host, port, auth_user, auth_password)
        self.roles = self.get_roles()
        self.changed = False

    def get_roles(self):
        roles = {}
        # For roles there will only every be a single group
        for record in self.execute_cmd("show roles")["groups"][0]["records"]:
            if record["Role"]["raw"] == "null":
                roles[record["Role"]["raw"]] = []
            else:
                roles[record["Role"]["raw"]] = record["Privileges"]["raw"]
        return roles

    def manage_role(self, role, privileges, state):
        if state == "absent":
            return self.delete_role(role)
        if role not in self.roles:
            return self.create_role(role, privileges)
        return self.update_privs(role, privileges)

    def delete_role(self, role):
        if role in self.roles:
            result = self.execute_cmd(f"enable; manage acl delete role {role}")
            if self.failed:
                return f"Failed to delete role {role} with: {result}"
            self.changed = True
            return f"Deleted role {role}"
        return f"Role {role} does not exist so can't be deleted"

    def create_role(self, role, privileges):
        # Unfortunately we can only grant a single privelege at a time
        priv = ""
        if privileges:
            priv = privileges[0]

        result = self.execute_cmd(f"enable; manage acl create role {role} priv {priv}")
        if self.failed:
            return f"Failed to create role {role} with: {result}"
        self.changed = True

        for priv in privileges:
            result = self.execute_cmd(f"enable; manage acl grant role {role} priv {priv}")
            if self.failed:
                return f"Failed to grant role {role} privelege {priv} with: {result}"

        return f"Created role {role} with privileges {' '.join(privileges)}"

    def update_privs(self, role, privileges):
        privs_to_grant = []
        privs_to_revoke = []

        for priv in self.roles[role]:
            if priv not in privileges:
                privs_to_revoke.append(role)
        for priv in privileges:
            if priv not in self.roles[role]:
                privs_to_grant.append(role)

        msg = ""
        if privs_to_grant:
            for priv in privileges:
                result = self.execute_cmd(f"enable; manage acl grant role {role} priv {priv}")
                if self.failed:
                    return f"Failed to grant role {role} priv {priv} with: {result}"
                self.changed = True

        if privs_to_revoke:
            for priv in privileges:
                result = self.execute_cmd(f"enable; manage acl revoke role {role} priv {priv}")
                if self.failed:
                    return f"Failed to revoke privs {' '.join(privs_to_grant)} for role {role} with: {result}"
                self.changed = True

        return f"Updated role {role} granted privs {' '.join(privs_to_grant)} and revoked privs {' '.join(privs_to_revoke)}"


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        host=dict(type="str", required=True),
        port=dict(type="int", required=False, default=3000),
        auth_user=dict(type="str", required=False, default="admin"),
        auth_password=dict(type="str", required=False, default="admin"),
        state=dict(type="str", required=False, choices=["present", "absent"], default="present"),
        role=dict(type="str", required=True),
        privileges=dict(type="list", required=False, default=[]),
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(changed=False, failed=False, original_message="", message="")

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    mg = ManageRoles(
        module.params["host"],
        module.params["port"],
        module.params["auth_user"],
        module.params["auth_password"],
    )
    res = mg.manage_role(
        module.params["role"],
        module.params["privileges"],
        module.params["state"],
    )
    # res = mg.get_users()
    result["failed"] = mg.failed
    result["changed"] = mg.changed

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    # result["original_message"] = module.params["name"]
    result["message"] = res

    # during the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result
    if mg.failed:
        module.fail_json(msg=res, **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
