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
from ansible_collections.aerospike.acl.plugins.module_utils.acl_common import ACLError, ACLWarning


class RoleGetError(Exception):
    pass


class RoleDeleteError(Exception):
    pass


class RoleCreateError(Exception):
    pass


class RoleUpdateError(Exception):
    pass


class ManageRoles(ACL):
    def __init__(self, asadm_config, asadm_cluster, asadm_user, asadm_password):
        super().__init__(asadm_config, asadm_cluster, asadm_user, asadm_password)
        self.changed = False
        self.failed = False
        self.message = ""
        try:
            self.get_roles()
        except RoleGetError as err:
            self.failed = True
            self.message = f"Failed to get roles with: {err}"
            return

    def get_roles(self):
        self.roles = {}
        try:
            # For roles there will only every be a single group with the default roles/privileges present.
            for record in self.execute_cmd("show roles")["groups"][0]["records"]:
                if record["Privileges"]["raw"] == "null":
                    self.roles[record["Role"]["raw"]] = []
                else:
                    self.roles[record["Role"]["raw"]] = record["Privileges"]["raw"]
        except (ACLError, ACLWarning) as err:
            raise RoleGetError(err)

    def manage_role(self, role, privileges, state):
        try:
            if state == "absent":
                return self.delete_role(role)
            if role not in self.roles:
                return self.create_role(role, privileges)
            grants = self.privileges_to_grant(role, privileges)
            revokes = self.privileges_to_revoke(role, privileges)
            return self.update_privs(role, grants, revokes)
        except RoleDeleteError as err:
            self.message = f"Failed to delete role {role} with: {err}"
        except RoleCreateError as err:
            self.message = f"Failed to create role {role} with: {err}"
        except RoleUpdateError as err:
            self.message = f"Failed to update role {role} with: {err}"

    def delete_role(self, role):
        if role in self.roles:
            try:
                self.execute_cmd(f"enable; manage acl delete role {role}")
            except (ACLError, ACLWarning) as err:
                self.failed = True
                raise RoleDeleteError(err)
            self.changed = True
            self.message = f"Deleted role {role}"
            return
        self.message = f"Role {role} does not exist so can't be deleted"

    def create_role(self, role, privileges):
        # Unfortunately the asadm interface only allows adding a single privelege at a time.
        priv = ""
        if privileges:
            priv = privileges[0]

        try:
            self.execute_cmd(f"enable; manage acl create role {role} priv {priv}")
            self.changed = True

            for priv in privileges[1:]:
                self.execute_cmd(f"enable; manage acl grant role {role} priv {priv}")
        except (ACLError, ACLWarning) as err:
            self.failed = True
            raise RoleCreateError(err)

        self.message = f"Created role {role} with privileges {' '.join(privileges)}"

    def privileges_to_grant(self, role, privileges):
        return [p for p in privileges if p not in self.roles[role]]

    def privileges_to_revoke(self, role, privileges):
        return [p for p in self.roles[role] if p not in privileges]

    def update_privs(self, role, grants, revokes):
        try:
            for grant in grants:
                self.execute_cmd(f"enable; manage acl grant role {role} priv {grant}")
                self.changed = True

            for revoke in revokes:
                self.execute_cmd(f"enable; manage acl revoke role {role} priv {revoke}")
                self.changed = True
        except (ACLError, ACLWarning) as err:
            self.failed = True
            raise RoleUpdateError(err)

        if not self.changed:
            self.message = f"No updates needed for role {role}"
        if grants and revokes:
            self.message = f"Updated role {role} granted privileges {' '.join(grants)} and revoked priveleges {' '.join(revokes)}"
        if grants and not revokes:
            self.message = f"Updated role {role} granted privileges {' '.join(grants)}"
        if not grants and revokes:
            self.message = f"Updated role {role} revoked priveleges {' '.join(revokes)}"


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        asadm_config=dict(type="str", required=False, default="/etc/aerospike/astools.conf"),
        asadm_cluster=dict(type="str", required=False, default="test"),
        asadm_user=dict(type="str", required=False, default="admin"),
        asadm_password=dict(type="str", required=False, default="admin"),
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
        module.params["asadm_config"],
        module.params["asadm_cluster"],
        module.params["asadm_user"],
        module.params["asadm_password"],
    )

    mg.manage_role(
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
    result["message"] = mg.message

    # during the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result
    if mg.failed:
        module.fail_json(msg=mg.message, **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
