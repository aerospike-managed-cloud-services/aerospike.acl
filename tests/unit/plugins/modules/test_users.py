import pytest
from ansible_collections.aerospike.acl.plugins.module_utils.acl_common import (
    ACLError, ACLWarning)
from ansible_collections.aerospike.acl.plugins.modules import users
from ansible_collections.aerospike.acl.plugins.modules.users import (
    ManageUsers, UserCreateError, UserDeleteError, UserPasswordUpdateError,
    UserRoleUpdateError)


def test_get_users_happy_path(mocker):
    def mock_execute_cmd(self, cmd):
        return {
            "groups": [
                {"records": [{"User": {"raw": "test-user"}, "Roles": {"raw": ["user-admin"]}}]}
            ]
        }

    def mock_manage_user(self, user, password, roles, state):
        return

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )
    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.modules.users.ManageUsers.manage_user",
        mock_manage_user,
    )

    mg = users.ManageUsers("", "", "", "")
    mg.manage_user("", "", "", "")

    assert mg.users == {"test-user": ["user-admin"]}
    assert mg.failed == False
    assert mg.message == ""


def test_get_users_null_roles(mocker):
    def mock_execute_cmd(self, cmd):
        return {"groups": [{"records": [{"User": {"raw": "test-user"}, "Roles": {"raw": "null"}}]}]}

    def mock_manage_user(self, user, password, roles, state):
        return

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )
    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.modules.users.ManageUsers.manage_user",
        mock_manage_user,
    )

    mg = users.ManageUsers("", "", "", "")
    mg.manage_user("", "", "", "")

    assert mg.users == {"test-user": []}
    assert mg.failed == False
    assert mg.message == ""


def test_get_users_acl_error(mocker):
    def mock_execute_cmd(self, cmd):
        raise ACLError("Ohh no there was an error!!")

    def mock_manage_user(self, user, password, roles, state):
        return

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )
    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.modules.users.ManageUsers.manage_user",
        mock_manage_user,
    )

    mg = users.ManageUsers("", "", "", "")
    mg.manage_user("", "", "", "")

    assert mg.message == "Failed to get users with: Ohh no there was an error!!"
    assert mg.failed == True


def test_get_users_acl_warning(mocker):
    def mock_execute_cmd(self, cmd):
        raise ACLWarning("Ohh no there was a warning!!")

    def mock_manage_user(self, user, password, roles, state):
        return

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )
    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.modules.users.ManageUsers.manage_user",
        mock_manage_user,
    )

    mg = users.ManageUsers("", "", "", "")
    mg.manage_user("", "", "", "")

    assert mg.message == "Failed to get users with: Ohh no there was a warning!!"
    assert mg.failed == True


def test_manage_user_delete_happy(mocker):
    def mock_execute_cmd(self, cmd):
        return {
            "groups": [{"records": [{"User": {"raw": "foo"}, "Roles": {"raw": ["user-admin"]}}]}]
        }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    spy = mocker.spy(ManageUsers, "delete_user")

    mg = users.ManageUsers("", "", "", "")
    mg.manage_user("foo", "", "", "absent")

    assert mg.users == {"foo": ["user-admin"]}
    assert spy.call_count == 1
    assert mg.message == "Deleted user foo"
    assert mg.failed == False
    assert mg.changed == True


def test_manage_user_delete_no_user(mocker):
    def mock_execute_cmd(self, cmd):
        return {
            "groups": [{"records": [{"User": {"raw": "foo"}, "Roles": {"raw": ["user-admin"]}}]}]
        }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    spy = mocker.spy(ManageUsers, "delete_user")

    mg = users.ManageUsers("", "", "", "")
    mg.manage_user("bar", "", "", "absent")

    assert mg.users == {"foo": ["user-admin"]}
    assert spy.call_count == 1
    assert mg.message == "User bar does not exist so can't be deleted"
    assert mg.failed == False
    assert mg.changed == False


def test_manage_user_delete_error(mocker):
    def mock_get_users(self):
        self.users = {"foo": []}
        return

    def mock_execute_cmd(self, cmd):
        raise ACLError("Ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.modules.users.ManageUsers.get_users",
        mock_get_users,
    )
    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    spy = mocker.spy(ManageUsers, "delete_user")

    mg = users.ManageUsers("", "", "", "")
    mg.manage_user("foo", "", "", "absent")

    assert spy.call_count == 1
    assert mg.message == "Failed to delete user foo with: Ohh no there was an error!!"
    assert mg.failed == True
    assert mg.changed == False


def test_manage_user_create_happy(mocker):
    def mock_get_users(self):
        self.users = {}
        return

    def mock_execute_cmd(self, cmd):
        return

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.modules.users.ManageUsers.get_users",
        mock_get_users,
    )
    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    spy = mocker.spy(ManageUsers, "create_user")

    mg = users.ManageUsers("", "", "", "")
    mg.manage_user("foo", "", ["baz", "biz"], "present")

    assert spy.call_count == 1
    assert mg.message == "Created user foo with roles baz biz"
    assert mg.failed == False
    assert mg.changed == True


def test_manage_user_create_error(mocker):
    def mock_get_users(self):
        self.users = {}
        return

    def mock_execute_cmd(self, cmd):
        raise ACLError("Ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.modules.users.ManageUsers.get_users",
        mock_get_users,
    )
    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    spy = mocker.spy(ManageUsers, "create_user")

    mg = users.ManageUsers("", "", "", "")
    mg.manage_user("foo", "", "", "present")

    assert spy.call_count == 1
    assert mg.message == "Failed to create user foo with: Ohh no there was an error!!"
    assert mg.failed == True
    assert mg.changed == False


def test_manage_user_update_happy(mocker):
    def mock_execute_cmd(self, cmd):
        return {
            "groups": [
                {"records": [{"User": {"raw": "foo"}, "Roles": {"raw": ["a", "2", "c", "d"]}}]}
            ]
        }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    spy = mocker.spy(ManageUsers, "update_user")

    mg = users.ManageUsers("", "", "", "")
    mg.manage_user("foo", "biz", ["a", "b", "c"], "present")

    assert spy.call_count == 1
    assert mg.message == "Updated user foo password and granted roles b and revoked roles 2 d"
    assert mg.failed == False
    assert mg.changed == True


def test_manage_user_update_error_password(mocker):
    def mock_execute_cmd(self, cmd):
        if cmd == "show users":
            return {
                "groups": [
                    {"records": [{"User": {"raw": "foo"}, "Roles": {"raw": ["a", "2", "c", "d"]}}]}
                ]
            }
        if "set-password" in cmd:
            raise ACLError("Ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    spy = mocker.spy(ManageUsers, "update_user")

    mg = users.ManageUsers("", "", "", "")
    mg.manage_user("foo", "biz", ["a", "b", "c"], "present")

    assert spy.call_count == 1
    assert mg.message == "Failed to update password for user foo with: Ohh no there was an error!!"
    assert mg.failed == True
    assert mg.changed == True


def test_manage_user_update_error_role(mocker):
    def mock_execute_cmd(self, cmd):
        if cmd == "show users":
            return {
                "groups": [
                    {"records": [{"User": {"raw": "foo"}, "Roles": {"raw": ["a", "2", "c", "d"]}}]}
                ]
            }
        if "grant" in cmd or "revoke" in cmd:
            raise ACLError("Ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    spy = mocker.spy(ManageUsers, "update_user")

    mg = users.ManageUsers("", "", "", "")
    mg.manage_user("foo", "biz", ["a", "b", "c"], "present")

    assert spy.call_count == 1
    assert mg.message == "Failed to update roles for user foo with: Ohh no there was an error!!"
    assert mg.failed == True
    assert mg.changed == False


def test_delete_user_happy_exists(mocker):
    def mock_execute_cmd(self, cmd):
        if cmd == "show users":
            return {
                "groups": [
                    {"records": [{"User": {"raw": "foo"}, "Roles": {"raw": ["a", "2", "c", "d"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = users.ManageUsers("", "", "", "")
    mg.delete_user("foo")

    assert mg.message == "Deleted user foo"
    assert mg.failed == False
    assert mg.changed == True


def test_delete_user_happy_does_not_exist(mocker):
    def mock_execute_cmd(self, cmd):
        if cmd == "show users":
            return {"groups": [{"records": [{"User": {"raw": "bix"}, "Roles": {"raw": []}}]}]}

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = users.ManageUsers("", "", "", "")
    mg.delete_user("foo")

    assert mg.message == "User foo does not exist so can't be deleted"
    assert mg.failed == False
    assert mg.changed == False


def test_delete_user_error(mocker):
    def mock_execute_cmd(self, cmd):
        if cmd == "show users":
            return {"groups": [{"records": [{"User": {"raw": "foo"}, "Roles": {"raw": []}}]}]}
        if "delete user" in cmd:
            raise ACLError("ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = users.ManageUsers("", "", "", "")

    with pytest.raises(UserDeleteError) as err:
        mg.delete_user("foo")

    assert "ohh no there was an error!!" in str(err.value)
    assert mg.failed == True
    assert mg.changed == False


def test_create_user_happy_exists(mocker):
    def mock_execute_cmd(self, cmd):
        if cmd == "show users":
            return {
                "groups": [
                    {"records": [{"User": {"raw": "foo"}, "Roles": {"raw": ["a", "2", "c", "d"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = users.ManageUsers("", "", "", "")
    mg.create_user("bar", "", ["1", "2", "3"])

    assert mg.message == "Created user bar with roles 1 2 3"
    assert mg.failed == False
    assert mg.changed == True


def test_create_user_error(mocker):
    def mock_execute_cmd(self, cmd):
        if cmd == "show users":
            return {"groups": [{"records": [{"User": {"raw": "foo"}, "Roles": {"raw": []}}]}]}
        if "create user" in cmd:
            raise ACLError("ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = users.ManageUsers("", "", "", "")

    with pytest.raises(UserCreateError) as err:
        mg.create_user("foo", "", [])

    assert "ohh no there was an error!!" in str(err.value)
    assert mg.failed == True
    assert mg.changed == False


def test_roles_to_grant_happy(mocker):
    def mock_execute_cmd(self, cmd):
        if cmd == "show users":
            return {
                "groups": [
                    {"records": [{"User": {"raw": "foo"}, "Roles": {"raw": ["a", "2", "c", "d"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = users.ManageUsers("", "", "", "")
    grants = mg.roles_to_grant("foo", ["1", "2", "e"])

    assert grants == ["1", "e"]


def test_roles_to_revoke_happy(mocker):
    def mock_execute_cmd(self, cmd):
        if cmd == "show users":
            return {
                "groups": [
                    {"records": [{"User": {"raw": "foo"}, "Roles": {"raw": ["a", "2", "c", "d"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = users.ManageUsers("", "", "", "")
    revokes = mg.roles_to_revoke("foo", ["1", "2", "e"])

    assert revokes == ["a", "c", "d"]


def test_update_user_happy_all(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show users":
            return {
                "groups": [
                    {"records": [{"User": {"raw": "bar"}, "Roles": {"raw": ["a", "2", "c", "d"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = users.ManageUsers("", "", "", "")
    mg.update_user("bar", "pass", ["1", "3"], ["c", "d"])

    assert commands == [
        "show users",
        "enable; manage acl grant user bar roles 1 3",
        "enable; manage acl revoke user bar roles c d",
        "enable; manage acl set-password user bar password pass",
    ]

    assert mg.message == "Updated user bar password and granted roles 1 3 and revoked roles c d"
    assert mg.failed == False
    assert mg.changed == True


def test_update_user_happy_no_role_changes(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show users":
            return {
                "groups": [
                    {"records": [{"User": {"raw": "bar"}, "Roles": {"raw": ["a", "2", "c", "d"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = users.ManageUsers("", "", "", "")
    mg.update_user("bar", "pass", [], [])

    assert commands == [
        "show users",
        "enable; manage acl set-password user bar password pass",
    ]

    assert mg.message == "Updated user bar password"
    assert mg.failed == False
    assert mg.changed == True


def test_update_user_happy_grants(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show users":
            return {
                "groups": [
                    {"records": [{"User": {"raw": "bar"}, "Roles": {"raw": ["a", "2", "c", "d"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = users.ManageUsers("", "", "", "")
    mg.update_user("bar", "pass", ["a"], [])

    assert commands == [
        "show users",
        "enable; manage acl grant user bar roles a",
        "enable; manage acl set-password user bar password pass",
    ]

    assert mg.message == "Updated user bar password and granted roles a"
    assert mg.failed == False


def test_update_user_happy_revokes(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show users":
            return {
                "groups": [
                    {"records": [{"User": {"raw": "bar"}, "Roles": {"raw": ["a", "2", "c", "d"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = users.ManageUsers("", "", "", "")
    mg.update_user("bar", "pass", [], ["a"])

    assert commands == [
        "show users",
        "enable; manage acl revoke user bar roles a",
        "enable; manage acl set-password user bar password pass",
    ]

    assert mg.message == "Updated user bar password and revoked roles a"
    assert mg.failed == False


def test_update_user_error_role_update_grants(mocker):
    def mock_execute_cmd(self, cmd):
        if cmd == "show users":
            return {
                "groups": [
                    {"records": [{"User": {"raw": "bar"}, "Roles": {"raw": ["a", "2", "c", "d"]}}]}
                ]
            }
        if "grant user" in cmd:
            raise ACLError("ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = users.ManageUsers("", "", "", "")

    with pytest.raises(UserRoleUpdateError) as err:
        mg.update_user("foo", "", ["a"], [])

    assert "ohh no there was an error!!" in str(err.value)

    assert mg.failed == True
    assert mg.changed == False


def test_update_user_error_role_update_revokes(mocker):
    def mock_execute_cmd(self, cmd):
        if cmd == "show users":
            return {
                "groups": [
                    {"records": [{"User": {"raw": "bar"}, "Roles": {"raw": ["a", "2", "c", "d"]}}]}
                ]
            }
        if "revoke user" in cmd:
            raise ACLError("ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = users.ManageUsers("", "", "", "")

    with pytest.raises(UserRoleUpdateError) as err:
        mg.update_user("foo", "", [], ["a"])

    assert "ohh no there was an error!!" in str(err.value)

    assert mg.failed == True
    assert mg.changed == False


def test_update_user_error_password(mocker):
    def mock_execute_cmd(self, cmd):
        if cmd == "show users":
            return {
                "groups": [
                    {"records": [{"User": {"raw": "bar"}, "Roles": {"raw": ["a", "2", "c", "d"]}}]}
                ]
            }
        if "set-password" in cmd:
            raise ACLError("ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = users.ManageUsers("", "", "", "")

    with pytest.raises(UserPasswordUpdateError) as err:
        mg.update_user("foo", "", [], [])

    assert "ohh no there was an error!!" in str(err.value)

    assert mg.failed == True
    assert mg.changed == False
