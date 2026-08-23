
import importlib.util


def compile_rule(rule_name, rule_body):
    src_path = "rules/%s.py" % rule_name
    with open(src_path, "w") as f:
        f.write("def apply(price):\n    return " + rule_body + "\n")
    spec = importlib.util.spec_from_file_location(rule_name, src_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.apply


def build_handler(field, transform):
    source = "def handler(x):\n    x['%s'] = %s\n    return x" % (field, transform)
    ns = {}
    exec(compile(source, "<rule>", "exec"), ns)
    return ns["handler"]
