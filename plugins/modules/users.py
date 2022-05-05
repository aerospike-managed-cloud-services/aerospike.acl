#!/usr/bin/python

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.aerospike.acl.plugins.module_utils.acl_common import (
    ACL,
    ACLError,
    ACLWarning,
)


class UserGetError(Exception):
    pass


class UserDeleteError(Exception):
    pass


class UserCreateError(Exception):
    pass


class UserRoleUpdateError(Exception):
    pass


class UserPasswordUpdateError(Exception):
    pass


class ManageUsers(ACL):
    def __init__(self, asadm_config, asadm_cluster, asadm_user, asadm_password):
        super().__init__(asadm_config, asadm_cluster, asadm_user, asadm_password)
        self.changed = False
        self.failed = False
        self.message = ""
        try:
            self.get_users()
        except UserGetError as err:
            self.message = f"Failed to get users with: {err}"
            return

    def get_users(self):
        self.users = {}
        try:
            # For users there will only every be a single group and at least one user (admin).
            for record in self.execute_cmd("show users")["groups"][0]["records"]:
                if record["Roles"]["raw"] == "null":
                    self.users[record["User"]["raw"]] = []
                else:
                    self.users[record["User"]["raw"]] = record["Roles"]["raw"]
        except (ACLError, ACLWarning) as err:
            self.failed = True
            raise UserGetError(err)

    def manage_user(self, user, password, roles, state):
        try:
            if state == "absent":
                return self.delete_user(user)
            if user not in self.users:
                return self.create_user(user, password, roles)

            grants = self.roles_to_grant(user, roles)
            revokes = self.roles_to_revoke(user, roles)
            return self.update_user(user, password, grants, revokes)

        except UserDeleteError as err:
            self.message = f"Failed to delete user {user} with: {err}"
        except UserCreateError as err:
            self.message = f"Failed to create user {user} with: {err}"
        except UserPasswordUpdateError as err:
            self.message = f"Failed to update password for user {user} with: {err}"
        except UserRoleUpdateError as err:
            self.message = f"Failed to update roles for user {user} with: {err}"

    def delete_user(self, user):
        if user in self.users:
            try:
                self.execute_cmd(f"enable; manage acl delete user {user}")
            except (ACLError, ACLWarning) as err:
                self.failed = True
                raise UserDeleteError(err)
            self.changed = True
            self.message = f"Deleted user {user}"
            return
        self.message = f"User {user} does not exist so can't be deleted"

    def create_user(self, user, password, roles):
        try:
            self.execute_cmd(
                f"enable; manage acl create user {user} password {password} roles {roles}"
            )
            self.changed = True
        except (ACLError, ACLWarning) as err:
            self.failed = True
            raise UserCreateError(err)
        self.message = f"Created user {user} with roles {' '.join(roles)}"

    def roles_to_grant(self, user, roles):
        return [r for r in roles if r not in self.users[user]]

    def roles_to_revoke(self, user, roles):
        return [r for r in self.users[user] if r not in roles]

    def update_user(self, user, password, grants, revokes):
        try:
            if grants:
                self.execute_cmd(f"enable; manage acl grant user {user} roles {' '.join(grants)}")
                self.changed = True
            if revokes:
                self.execute_cmd(f"enable; manage acl revoke user {user} roles {' '.join(revokes)}")
                self.changed = True
        except (ACLError, ACLWarning) as err:
            self.failed = True
            raise UserRoleUpdateError(err)

        try:
            # We always have to update the PW since we can't ask the DB what the current PW is.
            self.execute_cmd(f"enable; manage acl set-password user {user} password {password}")
            self.changed = True
        except (ACLError, ACLWarning) as err:
            self.failed = True
            raise UserPasswordUpdateError(err)

        if not grants and not revokes:
            self.message = f"Updated user {user} password"
        if grants and revokes:
            self.message = f"Updated user {user} password and granted roles {' '.join(grants)} and revoked roles {' '.join(revokes)}"
        if grants and not revokes:
            self.message = f"Updated user {user} password and granted roles {' '.join(grants)}"
        if not grants and revokes:
            self.message = f"Updated user {user} password and revoked roles {' '.join(revokes)}"


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        asadm_config=dict(type="str", required=False, default="/etc/aerospike/astools.conf"),
        asadm_cluster=dict(type="str", required=False, default="test"),
        asadm_user=dict(type="str", required=False, default="admin"),
        asadm_password=dict(type="str", required=False, default="admin"),
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
        module.params["asadm_config"],
        module.params["asadm_cluster"],
        module.params["asadm_user"],
        module.params["asadm_password"],
    )
    mg.manage_user(
        module.params["user"],
        module.params["password"],
        module.params["roles"],
        module.params["state"],
    )
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
