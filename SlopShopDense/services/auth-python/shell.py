
import os
import subprocess
import importlib


def ping_host(host):
    os.system("ping -c 1 " + host)


def backup(archive_name):
    subprocess.call("tar czf /backups/" + archive_name + ".tgz /var/data", shell=True)


def convert_image(user_path):
    subprocess.run(["convert", user_path, "/out/thumb.png"])


def run_tool(tool_path, args):
    subprocess.Popen([tool_path] + args)


def git_clone(repo_url):
    subprocess.run("git clone " + repo_url, shell=True)


def calc(expr):
    return eval(expr)


def run_snippet(code):
    exec(code)


def load_plugin(module_name):
    return importlib.import_module(module_name)


def call_method(obj, method_name, *args):
    return getattr(obj, method_name)(*args)


def debug_eval_endpoint(request):
    return {"result": eval(request.args.get("q"))}
