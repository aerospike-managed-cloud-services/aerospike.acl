#!/usr/bin/env python3

import pytest

from ansible_collections.aerospike.acl.plugins.module_utils.acl_common import (
    ACL,
    ACLError,
    ACLWarning,
)


class RunMock:
    def __init__(self, cmd, returncode, stdout, stderr):
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout.encode()
        self.stderr = stderr.encode()


def test_execute_cmd_happy(mocker):
    commands = []

    def mock_run(cmd, stdout="foo", stderr="bar"):
        commands.append(cmd)
        return RunMock(cmd, 0, "", "")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.run",
        mock_run,
    )

    acl = ACL("cfg_path", "user", "password", "instance")

    acl.execute_cmd("this is a command")
    assert commands[0] == [
        "asadm",
        "--config-file=cfg_path",
        "--user=password",
        "--password=instance",
        "--instance=user",
        "-e",
        "this is a command",
        "--json",
    ]


def test_execute_cmd_error(mocker):
    commands = []

    def mock_run(cmd, stdout="foo", stderr="bar"):
        commands.append(cmd)
        return RunMock(cmd, 1, "ohh no there was an error!!", "")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.run",
        mock_run,
    )

    acl = ACL("cfg_path", "user", "password", "instance")

    with pytest.raises(ACLError) as err:
        acl.execute_cmd("this is a command")

    assert "ohh no there was an error!!" in str(err.value)
    assert commands[0] == [
        "asadm",
        "--config-file=cfg_path",
        "--user=password",
        "--password=instance",
        "--instance=user",
        "-e",
        "this is a command",
        "--json",
    ]


def test_parse_error(mocker):
    acl = ACL("cfg_path", "user", "password", "instance")
    result = acl._parse_error(
        "\n".join(["ERROR: ohh no there was an error!!", "here's more information"])
    )

    assert "ERROR: ohh no there was an error!!" == result


def test_parse_results_no_json(mocker):
    acl = ACL("cfg_path", "user", "password", "instance")
    result = acl._parse_results("\n".join(["foo", "  here's a weird line "]))

    assert result == None


def test_parse_results_json(mocker):
    acl = ACL("cfg_path", "user", "password", "instance")
    result = acl._parse_results(
        "\n".join(["foo", "  here's a weird line ", "{", '  "key":"value"', "}"])
    )

    assert {"key": "value"} == result


def test_parse_result_warning(mocker):
    acl = ACL("cfg_path", "user", "password", "instance")

    with pytest.raises(ACLWarning) as err:
        acl._parse_results(
            "\n".join(
                [
                    "WARNING: this is a warning",
                    "  here's a weird line ",
                    "{",
                    '  "key":"value"',
                    "}",
                ]
            )
        )

    assert "WARNING: this is a warning" in str(err.value)
