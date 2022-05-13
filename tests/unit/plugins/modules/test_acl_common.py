#!/usr/bin/env python3

import pytest
from ansible_collections.aerospike.acl.plugins.module_utils.acl_common import (
    ACL,
    ACLError,
    ACLWarning,
)


@pytest.fixture
def generic_acl():
    return ACL("cfg_path", "user", "password", "instance")


class RunMock:
    def __init__(self, cmd, returncode, stdout, stderr):
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout.encode()
        self.stderr = stderr.encode()


def test_execute_cmd_happy(mocker, generic_acl):
    commands = []

    def mock_run(cmd, stdout="foo", stderr="bar"):
        commands.append(cmd)
        return RunMock(cmd, 0, "", "")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.run",
        mock_run,
    )

    generic_acl.execute_cmd("this is a command")
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


def test_execute_cmd_error(mocker, generic_acl):
    commands = []

    def mock_run(cmd, stdout="foo", stderr="bar"):
        commands.append(cmd)
        return RunMock(cmd, 1, "ohh no there was an error!!", "")

    mocker.patch(
        "ansible_collections.aerospike.acl.plugins.module_utils.acl_common.run",
        mock_run,
    )

    with pytest.raises(ACLError) as err:
        generic_acl.execute_cmd("this is a command")

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


def test_parse_error(mocker, generic_acl):
    result = generic_acl._parse_error(
        "\n".join(["ERROR: ohh no there was an error!!", "here's more information"])
    )

    assert "ERROR: ohh no there was an error!!" == result


def test_parse_results_no_json(mocker, generic_acl):
    result = generic_acl._parse_results("\n".join(["foo", "  here's a weird line "]))

    assert result == None


def test_parse_results_json(mocker, generic_acl):
    result = generic_acl._parse_results(
        "\n".join(["foo", "  here's a weird line ", "{", '  "key":"value"', "}"])
    )

    assert {"key": "value"} == result


def test_parse_result_warning(mocker, generic_acl):

    with pytest.raises(ACLWarning) as err:
        generic_acl._parse_results(
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


def test_single_token(generic_acl):
    assert generic_acl.single_token("thisshouldnotfail") == True
    assert generic_acl.single_token("this should fail") == False
    assert generic_acl.single_token("this^should(fail") == False
