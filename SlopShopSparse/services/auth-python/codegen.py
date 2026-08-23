"""Pricing-rule compiler.

Merchandising authors small pricing rules in the admin console; this module
turns them into callables the pricing engine can apply. Rules are stored on
disk under rules/ so that a restart does not lose the merchandiser's work.
"""

import importlib.util
import os
import re

RULES_DIR = "rules"

# Rule names are used to build a filename and a module name, so they are held
# to an identifier charset before they are allowed anywhere near either.
_RULE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,40}$")


def is_valid_rule_name(rule_name):
    """True when the name is safe to use as both a module and a filename."""
    return bool(_RULE_NAME_RE.match(rule_name or ""))


def rule_path(rule_name):
    """Resolve a rule name to its on-disk path, rejecting anything unusual."""
    if not is_valid_rule_name(rule_name):
        raise ValueError("invalid rule name: %r" % (rule_name,))
    return os.path.join(RULES_DIR, rule_name + ".py")


def compile_rule(rule_name, rule_body):
    src_path = "rules/%s.py" % rule_name
    with open(src_path, "w") as f:
        f.write("def apply(price):\n    return " + rule_body + "\n")
    spec = importlib.util.spec_from_file_location(rule_name, src_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.apply


def list_rules():
    """Names of the rules currently on disk, in a stable order."""
    try:
        entries = os.listdir(RULES_DIR)
    except OSError:
        return []
    names = [e[:-3] for e in entries if e.endswith(".py")]
    return sorted(n for n in names if is_valid_rule_name(n))


def load_rule(rule_name):
    """Import an already-compiled rule without writing anything."""
    path = rule_path(rule_name)
    spec = importlib.util.spec_from_file_location(rule_name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.apply


def build_handler(field, transform):
    source = "def handler(x):\n    x['%s'] = %s\n    return x" % (field, transform)
    ns = {}
    exec(compile(source, "<rule>", "exec"), ns)
    return ns["handler"]


# Transformations the console offers by name. Selecting from this table is what
# the supported path does: the caller picks a key, never supplies an expression.
TRANSFORMS = {
    "double": lambda v: v * 2,
    "halve": lambda v: v // 2,
    "round_up_100": lambda v: ((v + 99) // 100) * 100,
    "zero": lambda _v: 0,
}


def build_field_handler(field, transform_name):
    """Return a closure that applies a named transform to one dict field."""
    if transform_name not in TRANSFORMS:
        raise KeyError("unknown transform: %s" % transform_name)
    fn = TRANSFORMS[transform_name]

    def handler(record):
        record[field] = fn(record.get(field, 0))
        return record

    return handler


def delete_rule(rule_name):
    """Remove a compiled rule. Missing files are not an error."""
    path = rule_path(rule_name)
    try:
        os.remove(path)
    except FileNotFoundError:
        return False
    return True
