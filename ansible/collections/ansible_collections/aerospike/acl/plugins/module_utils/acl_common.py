import json
import shlex
import subprocess
from subprocess import run


class ACLError(Exception):
    """asadm has responded with a non-zero return code."""

    pass


class ACLWarning(Exception):
    """asadm has responded with success but included a warning."""

    pass


class ACL:
    """Run an command with asadm handling errors."""

    def __init__(self, asadm_config, asadm_cluster, asadm_auth_mode, asadm_user, asadm_password):
        self.asadm_config = asadm_config
        self.asadm_cluster = asadm_cluster
        self.asadm_auth_mode = asadm_auth_mode
        self.asadm_user = asadm_user
        self.asadm_password = asadm_password

    def execute_cmd(self, command):
        """Run the command"""
        cmd = [
            "asadm",
            f"--config-file={self.asadm_config}",
            f"--auth={self.asadm_auth_mode}",
            f"--user={self.asadm_user}",
            f"--password={self.asadm_password}",
            f"--instance={self.asadm_cluster}",
            "-e",
            command,
            "--json",
        ]
        p = run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if p.returncode != 0:
            raise ACLError(self._parse_error(p.stdout.decode("utf-8")))
        return self._parse_results(p.stdout.decode("utf-8"))

    def _parse_error(self, failure):
        """
        Parse out errors only returning the first line which contains the message.
        """
        error = failure.split("\n")[0]
        return error

    def _parse_results(self, results):
        """
        Parse results of a succesful asadm command, if we're able to extract json return that
        otherwise return an empty response.
        """
        lines = results.split("\n")
        # A zero return code with warnings is possible, it's better to raise an exception than
        # to continue when this happens.
        if "WARNING" in lines[0]:
            raise ACLWarning(lines[0])

        data = []
        started_json = False
        for l in lines:
            if l == "{":
                started_json = True
            if started_json:
                data.append(l)
        try:
            return json.loads("\n".join(data))
        except json.decoder.JSONDecodeError:
            # The manage acl commands do not return json, we just care about success or failure.
            return

    def single_token(self, value):
        # asadm tokenizes input lines using the strategy below, we need to validate that the values
        # users give us tokenize to single strings, ref:  https://github.com/aerospike/aerospike-admin/blob/06cc2cb5a40e5115c2febb044da47d5a4106ded9/asadm.py#L270
        lexer = shlex.shlex(value)
        lexer.wordchars += ".*-:/_{}@"

        if len([t for t in lexer]) != 1:
            return False
        return True
