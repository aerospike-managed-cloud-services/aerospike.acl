#!/usr/bin/env python3
import json
import subprocess
from subprocess import run


class ACL:
    def __init__(self, host, port, auth_user, auth_password) -> None:
        self.host = host
        self.port = port
        self.auth_user = auth_user
        self.auth_password = auth_password
        self.failed = False

    def execute_cmd(self, command):
        # TODO add a timeout?
        # TODO error handling, define error messages
        cmd = [
            "asadm",
            f"--host={self.host}",
            f"--port={self.port}",
            "--no-config-file",
            f"--user={self.auth_user}",
            f"--password={self.auth_password}",
            "-e",
            command,
            "--json",
            # TODO ref instance and optionally set host/noconfig?
        ]
        p = run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if p.returncode != 0:
            self.failed = True
            # TODO parse out error and bubble it up
            return self._parse_error(p.stdout.decode("utf-8"))
        self.failed = False
        return self._parse_results(p.stdout.decode("utf-8"))

    def _parse_error(self, failure):
        error = failure.split("\n")[0]
        return error

    def _parse_results(self, results):
        # TODO look at underlying code to understand if the top two lines are always metadata
        try:
            return json.loads("\n".join(results.split("\n")[2:]))
        except json.decoder.JSONDecodeError:
            return results
