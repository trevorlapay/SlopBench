"""Process execution and dynamic loading helpers.

Anything in this module that spawns a process is called from the operations
console, which is reachable only from the internal network. That is a network
control, not an input control, so the argument handling still matters.
"""

import os
import shlex
import subprocess
import importlib

# Tools the console is allowed to invoke, mapped to their absolute paths so
# that a PATH change cannot redirect an invocation somewhere unexpected.
TOOL_PATHS = {
    "convert": "/usr/bin/convert",
    "tar": "/bin/tar",
    "git": "/usr/bin/git",
}

# Default timeout for any spawned process. A tool that has not finished by now
# is assumed to be wedged and is killed rather than waited on.
PROCESS_TIMEOUT_SECONDS = 30


def ping_host(host):
    os.system("ping -c 1 " + host)


def ping_host_argv(host):
    """Fixed argument vector, no shell, and a deadline on the child."""
    return subprocess.run(
        ["/bin/ping", "-c", "1", "--", host],
        shell=False,
        timeout=PROCESS_TIMEOUT_SECONDS,
        capture_output=True,
        check=False,
    ).returncode


def backup(archive_name):
    subprocess.call("tar czf /backups/" + archive_name + ".tgz /var/data", shell=True)


def backup_argv(archive_name):
    """Same archive, built with the name reduced to a single path component."""
    safe_name = os.path.basename(archive_name) + ".tgz"
    destination = os.path.join("/backups", safe_name)
    return subprocess.run(
        [TOOL_PATHS["tar"], "czf", destination, "/var/data"],
        shell=False,
        check=True,
    ).returncode


def convert_image(user_path):
    subprocess.run(["convert", user_path, "/out/thumb.png"])


def convert_image_terminated(user_path):
    """The -- separator stops a leading dash from being read as an option."""
    return subprocess.run(
        [TOOL_PATHS["convert"], "--", user_path, "/out/thumb.png"],
        shell=False,
        timeout=PROCESS_TIMEOUT_SECONDS,
        check=False,
    ).returncode


def run_tool(tool_path, args):
    subprocess.Popen([tool_path] + args)


def run_registered_tool(name, args):
    """Resolve the executable through the table above rather than trusting a path."""
    if name not in TOOL_PATHS:
        raise KeyError("unknown tool: %s" % name)
    argv = [TOOL_PATHS[name], "--"] + [str(a) for a in args]
    return subprocess.run(argv, shell=False, check=False).returncode


def git_clone(repo_url):
    subprocess.run("git clone " + repo_url, shell=True)


def describe_command(argv):
    """Render an argument vector the way a shell would show it, for the audit log.

    Quoting here is presentational only: nothing built by this function is
    handed back to a shell, it exists so the audit trail is readable.
    """
    return " ".join(shlex.quote(str(part)) for part in argv)


def calc(expr):
    return eval(expr)


def calc_literal(expr):
    """Evaluate a literal expression only; no names, calls, or attributes."""
    import ast

    return ast.literal_eval(expr)


def run_snippet(code):
    exec(code)


OPERATIONS = {
    "sum": lambda values: sum(values),
    "max": lambda values: max(values),
    "count": lambda values: len(values),
}


def run_operation(name, values):
    """Dispatch through a fixed table instead of executing caller-supplied text."""
    if name not in OPERATIONS:
        raise KeyError("unknown operation: %s" % name)
    return OPERATIONS[name](values)


def load_plugin(module_name):
    return importlib.import_module(module_name)


PLUGIN_MODULES = ("slopshop.plugins.pricing", "slopshop.plugins.shipping")


def load_registered_plugin(module_name):
    """Import only modules that shipped with the service."""
    if module_name not in PLUGIN_MODULES:
        raise ValueError("plugin not registered: %s" % module_name)
    return importlib.import_module(module_name)


def call_method(obj, method_name, *args):
    return getattr(obj, method_name)(*args)


def call_allowed_method(obj, method_name, allowed, *args):
    """Reflection narrowed to a caller-declared set of method names."""
    if method_name not in allowed:
        raise AttributeError("method not permitted: %s" % method_name)
    bound = getattr(obj, method_name)
    if not callable(bound):
        raise TypeError("%s is not callable" % method_name)
    return bound(*args)


def debug_eval_endpoint(request):
    return {"result": eval(request.args.get("q"))}


def status_endpoint(_request):
    """The supported diagnostics endpoint: fixed fields, no caller input."""
    return {"tools": sorted(TOOL_PATHS), "timeout": PROCESS_TIMEOUT_SECONDS}
