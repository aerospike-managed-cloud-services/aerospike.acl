__metaclass__ = type

DOCUMENTATION = r"""
---
module: users

short_description: Aerospike user ACL management

version_added: "1.0.0"

description: Create, update, and delete Aerospike DB users with asadm

options:
    asadm_config:
        description: The path to the asadm config file.
        required: false
        type: str
        default: /etc/aerospike/astools.conf
    asadm_cluster:
        description: The cluster name to target.
        required: false
        type: str
        default: test
    asadm_auth_mode:
        description: How to authenticate.
        required: false
        type: str
        default: INTERNAL
        choices: [ INTERNAL, EXTERNAL, PKI, EXTERNAL_INSECURE ]
    asadm_user:
        description: The user to run asadm with.
        required: false
        type: str
        default: admin
    asadm_password:
        description: The password to run asadm with.
        required: false
        type: str
        default: admin
    state:
        description: The desired state.
        required: false
        type: list
        default: present
        choices: [ present, absent, create_only ]
    user:
        description: The user to operate on.
        required: true
        type: str
    password:
        description: The user user password.
        required: false
        type: str
    roles:
        description: Roles the user should have.
        required: false
        type: list
        default: [  ]

author:
    - Aerospike Managed Customer Services <managedservices@aerospike.com>
"""

EXAMPLES = r"""
- name: Create/Update a user
  aerospike.acl.users:
    user: foo
    password: bar
    roles:
      - user-admin
      - data-admin

- name: Delete a user
  aerospike.acl.users:
    user: foo
    state: absent
"""

RETURN = r"""
changed:
    description: Boolean representing if the user was changed (or created).
    type: bool
    returned: always
    sample: true
failed:
    description: Boolean representing if the desired action on the user failed.
    type: bool
    returned: always
    sample: false
message:
    description: Message representing the action taken during task run or any failures.
    type: str
    returned: always
    sample: Created user foo with roles user-admin data-admin
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.aerospike.acl.plugins.module_utils.acl_common import (
    ACL,
    ACLError,
    ACLWarning,
)


class UserGetError(Exception):
    """Failure to get users."""

    pass


class UserDeleteError(Exception):
    """Failure to delete user."""

    pass


class UserCreateError(Exception):
    """Failure to create user."""

    pass


class UserRoleUpdateError(Exception):
    """Failure to update a users roles."""

    pass


class UserPasswordUpdateError(Exception):
    """Failure to update a users password."""

    pass


class ManageUsers(ACL):
    """Create, update and delete Aerospike users."""

    def __init__(self, asadm_config, asadm_cluster, asadm_auth_mode, asadm_user, asadm_password):
        super().__init__(asadm_config, asadm_cluster, asadm_auth_mode, asadm_user, asadm_password)
        self.changed = False
        self.failed = False
        self.message = ""
        try:
            self.get_users()
        except UserGetError as err:
            self.message = f"Failed to get users with: {err}"
            return

    def get_users(self):
        """
        Get users and their roles from Aerospike, then mutate into a dict with user names
        as keys and values as a list of the users roles.
        """
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
        """
        This is the entry point for actually making changes to or creating a new user. First we
        validate the input then depending on the specified state and whether the user already exists
        we delete, create, or update the user. Note that passwords always have to be updated since we
        can't query their current value from the DB.
        """
        if not self.single_token(user):
            self.message = (
                f"Failed to validate user '{user}' see Aerospike docs for valid name characters"
            )
            self.failed = True
            return
        if not password.isalnum():
            self.failed = True
            self.message = f"Failed to validate password '{password}' for user '{user}' see Aerospike docs for valid password characters"
            return
        for role in roles:
            if not self.single_token(role):
                self.failed = True
                self.message = f"Failed to validate role '{role}' for user '{user}' see Aerospike docs for valid role characters"
                return

        try:
            if state == "absent":
                return self.delete_user(user)
            if user not in self.users:
                return self.create_user(user, password, roles)
            if state == "create_only":
                self.changed = False
                self.failed = False
                self.message = f"User {user} exists"
                return True

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
        """Delete a user."""
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
        """Create a user."""
        try:
            self.execute_cmd(
                f"enable; manage acl create user {user} password {password} roles {' '.join(roles)}"
            )
            self.changed = True
        except (ACLError, ACLWarning) as err:
            self.failed = True
            raise UserCreateError(err)
        self.message = f"Created user {user} with roles {' '.join(roles)}"

    def roles_to_grant(self, user, roles):
        """Determine the roles to be granted."""
        return [r for r in roles if r not in self.users[user]]

    def roles_to_revoke(self, user, roles):
        """Determine the roles to be revoked."""
        return [r for r in self.users[user] if r not in roles]

    def update_user(self, user, password, grants, revokes):
        """Update the users roles and password."""
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
    """This is the interface to ansible code, from it we run the manage_users method."""

    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        asadm_config=dict(type="str", required=False, default="/etc/aerospike/astools.conf"),
        asadm_cluster=dict(type="str", required=False, default="test"),
        asadm_auth_mode=dict(type="str", choices=["INTERNAL", "EXTERNAL", "PKI", "EXTERNAL_INSECURE"], required=False, default="INTERNAL"),
        asadm_user=dict(type="str", required=False, default="admin"),
        asadm_password=dict(type="str", required=False, default="admin"),
        user=dict(type="str", required=True),
        password=dict(type="str", required=False),
        state=dict(type="str", required=False, choices=["present", "absent", "create_only"], default="present"),
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
        module.params["asadm_auth_mode"],
        module.params["asadm_user"],
        module.params["asadm_password"],
    )
    if not mg.failed:
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
