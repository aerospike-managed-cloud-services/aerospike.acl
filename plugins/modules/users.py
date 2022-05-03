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


class ManageUsers(ACL):
    def __init__(self, host, port, auth_user, auth_password) -> None:
        super().__init__(host, port, auth_user, auth_password)
        self.users = self.get_users()
        self.changed = False

    def get_users(self):
        users = {}
        # For users there will only every be a single group
        for record in self.execute_cmd("show users")["groups"][0]["records"]:
            if record["Roles"]["raw"] == "null":
                users[record["User"]["raw"]] = []
            else:
                users[record["User"]["raw"]] = record["Roles"]["raw"]
        return users

    def manage_user(self, user, password, roles, state):
        if state == "absent":
            return self.delete_user(user)
        if user not in self.users:
            return self.create_user(user, password, roles)
        result = self.update_password(user, password)
        if self.failed:
            return result
        message = self.update_roles(user, roles)
        if self.failed:
            return message
        if message:
            return f"Updated user {user} password and {message}"
        return f"Updated user {user} password"

    def create_user(self, user, password, roles):
        result = self.execute_cmd(
            f"enable; manage acl create user {user} password {password} roles {roles}"
        )
        if self.failed:
            return f"Failed to create user {user} with: {result}"
        self.changed = True
        return f"Created user {user} with roles {' '.join(roles)}"

    def delete_user(self, user):
        if user in self.users:
            result = self.execute_cmd(f"enable; manage acl delete user {user}")
            if self.failed:
                return f"Failed to delete user {user} with: {result}"
            self.changed = True
            return f"Deleted user {user}"
        return f"User {user} does not exist so can't be deleted"

    def update_roles(self, user, roles):
        roles_to_grant = []
        roles_to_revoke = []

        for role in self.users[user]:
            if role not in roles:
                roles_to_revoke.append(role)
        for role in roles:
            if role not in self.users[user]:
                roles_to_grant.append(role)

        msg = ""
        if roles_to_grant:
            result = self.execute_cmd(
                f"enable; manage acl grant user {user} roles {' '.join(roles_to_grant)}"
            )
            if self.failed:
                return (
                    f"Failed to grant user {user} roles {' '.join(roles_to_grant)} with: {result}"
                )
            self.changed = True
            msg = f"granted roles {' '.join(roles_to_grant)}"

        if roles_to_revoke:
            result = self.execute_cmd(
                f"enable; manage acl revoke user {user} roles {' '.join(roles_to_revoke)}"
            )
            if self.failed:
                return f"Failed to revoke roles {' '.join(roles_to_grant)} for user {user} with: {result}"
            self.changed = True
            msg += f" and revoked roles {' '.join(roles_to_revoke)}"

        return msg

    def update_password(self, user, password):
        result = self.execute_cmd(
            f"enable; manage acl set-password user {user} password {password}"
        )
        if self.failed:
            return f"Failed to set password for user {user} with: {result}"
        self.changed = True


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        host=dict(type="str", required=True),
        port=dict(type="int", required=False, default=3000),
        auth_user=dict(type="str", required=False, default="admin"),
        auth_password=dict(type="str", required=False, default="admin"),
        user=dict(type="str", required=True),
        password=dict(type="str", required=False),
        state=dict(type="str", required=False, choices=["present", "absent"], default="present"),
        roles=dict(type="list", required=False, default=[]),
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

    mg = ManageUsers(
        module.params["host"],
        module.params["port"],
        module.params["auth_user"],
        module.params["auth_password"],
    )
    res = mg.manage_user(
        module.params["user"],
        module.params["password"],
        module.params["roles"],
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
