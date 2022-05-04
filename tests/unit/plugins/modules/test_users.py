import pytest

from ansible_collections.aerospike.acl.plugins.modules import users
from ansible_collections.aerospike.acl.plugins.modules.users import ManageUsers
from ansible_collections.aerospike.acl.plugins.modules.users import (
    UserGetError,
    UserDeleteError,
    UserCreateError,
    UserRoleUpdateError,
    UserPasswordUpdateError,
)
from ansible_collections.aerospike.acl.plugins.module_utils.acl_common import ACLError, ACLWarning


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

    mg = users.ManageUsers("", "", "", "", "", "", "", "")

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

    mg = users.ManageUsers("", "", "", "", "", "", "", "")

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

    mg = users.ManageUsers("", "", "", "", "", "", "", "")
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

    mg = users.ManageUsers("", "", "", "", "", "", "", "")
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

    mg = users.ManageUsers("", "", "", "", "foo", "", "", "absent")

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

    mg = users.ManageUsers("", "", "", "", "bar", "", "", "absent")

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

    mg = users.ManageUsers("", "", "", "", "foo", "", "", "absent")

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

    mg = users.ManageUsers("", "", "", "", "foo", "", ["baz", "biz"], "present")

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

    mg = users.ManageUsers("", "", "", "", "foo", "", "", "present")

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

    mg = users.ManageUsers("", "", "", "", "foo", "biz", ["a", "b", "c"], "present")

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

    mg = users.ManageUsers("", "", "", "", "foo", "biz", ["a", "b", "c"], "present")

    assert spy.call_count == 1
    assert mg.message == "Failed to update password for user foo with: Ohh no there was an error!!"
    assert mg.failed == True
    assert mg.changed == True
