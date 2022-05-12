#!/usr/bin/env python3

import pytest
from ansible_collections.aerospike.acl.plugins.module_utils.acl_common import ACLError, ACLWarning
from ansible_collections.aerospike.acl.plugins.modules import roles
from ansible_collections.aerospike.acl.plugins.modules.roles import (
    RoleCreateError,
    RoleDeleteError,
    RoleUpdateError,
)


def test_get_roles_happy(mocker):
    def mock_execute_cmd(self, cmd):
        return {
            "groups": [
                {"records": [{"Role": {"raw": "test-role"}, "Privileges": {"raw": ["user-admin"]}}]}
            ]
        }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")

    assert mg.roles == {"test-role": ["user-admin"]}
    assert mg.failed == False
    assert mg.message == ""


def test_get_roles_null_privilege(mocker):
    def mock_execute_cmd(self, cmd):
        return {
            "groups": [{"records": [{"Role": {"raw": "test-role"}, "Privileges": {"raw": "null"}}]}]
        }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")

    assert mg.roles == {"test-role": []}
    assert mg.failed == False
    assert mg.message == ""


def test_get_roles_error(mocker):
    def mock_execute_cmd(self, cmd):
        raise ACLError("Ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")

    assert mg.failed == True
    assert mg.message == "Failed to get roles with: Ohh no there was an error!!"


def test_get_roles_warning(mocker):
    def mock_execute_cmd(self, cmd):
        raise ACLWarning("Ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")

    assert mg.failed == True
    assert mg.message == "Failed to get roles with: Ohh no there was an error!!"


def test_manage_role_user_validation_failure(mocker):
    def mock_execute_cmd(self, cmd):
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")
    mg.manage_role("not a valid role", ["write"], "absent")

    assert mg.failed == True
    assert mg.changed == False
    assert mg.message == "Failed to validate role 'not a valid role' see Aerospike docs for valid role characters"

def test_manage_role_priv_validation_failure(mocker):
    def mock_execute_cmd(self, cmd):
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")
    mg.manage_role("foo", ["write^read(scan"], "absent")

    assert mg.failed == True
    assert mg.changed == False
    assert mg.message == "Failed to validate privilege 'write^read(scan' for role 'foo' see Aerospike docs for valid privilege characters"

def test_manage_role_delete_happy(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")
    mg.manage_role("foo", [], "absent")

    assert mg.roles == {"foo": ["role-admin"]}
    assert commands == ["show roles", "enable; manage acl delete role foo"]
    assert mg.message == "Deleted role foo"
    assert mg.failed == False
    assert mg.changed == True


def test_manage_role_delete_no_role(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")
    mg.manage_role("bar", [], "absent")

    assert mg.roles == {"foo": ["role-admin"]}
    assert commands == ["show roles"]
    assert mg.message == "Role bar does not exist so can't be deleted"
    assert mg.failed == False
    assert mg.changed == False


def test_manage_role_delete_error(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }
        raise ACLError("Ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")
    mg.manage_role("foo", [], "absent")

    assert mg.message == "Failed to delete role foo with: Ohh no there was an error!!"
    assert mg.failed == True
    assert mg.changed == False


def test_manage_role_create_happy(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")
    mg.manage_role("fuzz", ["baz", "biz"], "present")

    assert commands == [
        "show roles",
        "enable; manage acl create role fuzz priv baz",
        "enable; manage acl grant role fuzz priv biz",
    ]
    assert mg.message == "Created role fuzz with privileges baz biz"
    assert mg.failed == False
    assert mg.changed == True


def test_manage_role_create_error(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }
        raise ACLError("Ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")
    mg.manage_role("fuzz", ["baz", "biz"], "present")

    assert commands == [
        "show roles",
        "enable; manage acl create role fuzz priv baz",
    ]
    assert mg.message == "Failed to create role fuzz with: Ohh no there was an error!!"
    assert mg.failed == True
    assert mg.changed == False


def test_manage_role_update_happy(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")
    mg.manage_role("foo", ["a", "b", "c"], "present")

    assert commands == [
        "show roles",
        "enable; manage acl grant role foo priv a",
        "enable; manage acl grant role foo priv b",
        "enable; manage acl grant role foo priv c",
        "enable; manage acl revoke role foo priv role-admin",
    ]
    assert (
        mg.message == "Updated role foo granted privileges a b c and revoked privileges role-admin"
    )
    assert mg.failed == False
    assert mg.changed == True


def test_manage_role_update_error(mocker):
    def mock_execute_cmd(self, cmd):
        if cmd == "show roles":
            return {
                "groups": [
                    {
                        "records": [
                            {"Role": {"raw": "foo"}, "Privileges": {"raw": ["a", "2", "c", "d"]}}
                        ]
                    }
                ]
            }
        if "grant" in cmd:
            raise ACLError("Ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")
    mg.manage_role("foo", ["a", "b", "c"], "present")

    assert mg.message == "Failed to update role foo with: Ohh no there was an error!!"
    assert mg.failed == True
    assert mg.changed == False


def test_delete_role_happy(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")
    mg.delete_role("foo")

    assert commands == [
        "show roles",
        "enable; manage acl delete role foo",
    ]
    assert mg.message == "Deleted role foo"
    assert mg.failed == False
    assert mg.changed == True


def test_delete_role_happy_does_not_exist(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")
    mg.delete_role("biz")

    assert commands == [
        "show roles",
    ]
    assert mg.message == "Role biz does not exist so can't be deleted"
    assert mg.failed == False
    assert mg.changed == False


def test_delete_role_error(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }
        if "delete role" in cmd:
            raise ACLError("ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")

    with pytest.raises(RoleDeleteError) as err:
        mg.delete_role("foo")

    assert commands == [
        "show roles",
        "enable; manage acl delete role foo",
    ]
    assert "ohh no there was an error!!" in str(err.value)
    assert mg.failed == True
    assert mg.changed == False


def test_create_role_happy(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")
    mg.create_role("biz", ["a", "b", "c"])

    assert commands == [
        "show roles",
        "enable; manage acl create role biz priv a",
        "enable; manage acl grant role biz priv b",
        "enable; manage acl grant role biz priv c",
    ]
    assert mg.message == "Created role biz with privileges a b c"
    assert mg.failed == False
    assert mg.changed == True


def test_create_role_error(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }
        if "create role" in cmd:
            raise ACLError("ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")

    with pytest.raises(RoleCreateError) as err:
        mg.create_role("foo", [])

    assert commands == [
        "show roles",
        "enable; manage acl create role foo priv ",
    ]
    assert "ohh no there was an error!!" in str(err.value)
    assert mg.failed == True
    assert mg.changed == False


def test_privileges_to_grant_happy(mocker):
    def mock_execute_cmd(self, cmd):
        if cmd == "show roles":
            return {
                "groups": [
                    {
                        "records": [
                            {"Role": {"raw": "foo"}, "Privileges": {"raw": ["a", "2", "c", "d"]}}
                        ]
                    }
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")
    grants = mg.privileges_to_grant("foo", ["1", "2", "e"])

    assert grants == ["1", "e"]


def test_privileges_to_revoke_happy(mocker):
    def mock_execute_cmd(self, cmd):
        if cmd == "show roles":
            return {
                "groups": [
                    {
                        "records": [
                            {"Role": {"raw": "foo"}, "Privileges": {"raw": ["a", "2", "c", "d"]}}
                        ]
                    }
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")
    revokes = mg.privileges_to_revoke("foo", ["1", "2", "e"])

    assert revokes == ["a", "c", "d"]


def test_update_role_happy(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")

    mg.update_privs("foo", ["a", "b"], ["role-admin"])

    assert commands == [
        "show roles",
        "enable; manage acl grant role foo priv a",
        "enable; manage acl grant role foo priv b",
        "enable; manage acl revoke role foo priv role-admin",
    ]
    assert mg.message == "Updated role foo granted privileges a b and revoked privileges role-admin"
    assert mg.failed == False
    assert mg.changed == True


def test_update_privs_error_grants(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }
        if "grant role" in cmd:
            raise ACLError("ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")

    with pytest.raises(RoleUpdateError) as err:
        mg.update_privs("foo", ["a", "b"], ["role-admin"])

    assert commands == [
        "show roles",
        "enable; manage acl grant role foo priv a",
    ]
    assert "ohh no there was an error!!" in str(err.value)
    assert mg.failed == True
    assert mg.changed == False


def test_update_privs_error_revoke(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }
        if "revoke role" in cmd:
            raise ACLError("ohh no there was an error!!")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")

    with pytest.raises(RoleUpdateError) as err:
        mg.update_privs("foo", ["a", "b"], ["role-admin"])

    assert commands == [
        "show roles",
        "enable; manage acl grant role foo priv a",
        "enable; manage acl grant role foo priv b",
        "enable; manage acl revoke role foo priv role-admin",
    ]
    assert "ohh no there was an error!!" in str(err.value)
    assert mg.failed == True
    assert mg.changed == True


def test_update_role_happy_no_updates(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")

    mg.update_privs("foo", [], [])

    assert commands == [
        "show roles",
    ]
    assert mg.message == "No updates needed for role foo"
    assert mg.failed == False
    assert mg.changed == False


def test_update_role_happy_grants(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")

    mg.update_privs("foo", ["a", "b"], [])

    assert commands == [
        "show roles",
        "enable; manage acl grant role foo priv a",
        "enable; manage acl grant role foo priv b",
    ]
    assert mg.message == "Updated role foo granted privileges a b"
    assert mg.failed == False
    assert mg.changed == True


def test_update_role_happy_revokes(mocker):
    commands = []

    def mock_execute_cmd(self, cmd):
        commands.append(cmd)
        if cmd == "show roles":
            return {
                "groups": [
                    {"records": [{"Role": {"raw": "foo"}, "Privileges": {"raw": ["role-admin"]}}]}
                ]
            }

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.ACL.execute_cmd",
        mock_execute_cmd,
    )

    mg = roles.ManageRoles("", "", "", "")

    mg.update_privs("foo", [], ["a", "b"])

    assert commands == [
        "show roles",
        "enable; manage acl revoke role foo priv a",
        "enable; manage acl revoke role foo priv b",
    ]
    assert mg.message == "Updated role foo revoked privileges a b"
    assert mg.failed == False
    assert mg.changed == True
