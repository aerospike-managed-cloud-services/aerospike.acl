#!/usr/bin/env python3
import json
import subprocess
from subprocess import run


class ACL:
    def __init__(self, asadm_config, asadm_cluster, asadm_user, asadm_password) -> None:
        self.asadm_config = asadm_config
        self.asadm_cluster = asadm_cluster
        self.asadm_user = asadm_user
        self.asadm_password = asadm_password
        self.failed = False

    def execute_cmd(self, command):
        cmd = [
            "asadm",
            f"--config-file={self.asadm_config}",
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
            self.failed = True
            # TODO parse out error and bubble it up
            return self._parse_error(p.stdout.decode("utf-8"))
        self.failed = False
        return self._parse_results(p.stdout.decode("utf-8"))

    def _parse_error(self, failure):
        error = failure.split("\n")[0]
        return error

    def _parse_results(self, results):
        # TODO look at underlying code to understand if the top three lines are always metadata
        try:
            return json.loads("\n".join(results.split("\n")[3:]))
        except json.decoder.JSONDecodeError:
            return results
