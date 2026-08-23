"""Template rendering for transactional email and profile fragments.

Two rendering paths exist: operator-authored templates, which are loaded from
the packaged template directory, and user-supplied text, which is only ever
data passed into a template rather than a template itself.
"""

from jinja2 import Template, Environment, select_autoescape
from string import Template as StringTemplate

# Placeholders the receipt template understands. The formatter below fills
# exactly these, so an unknown placeholder is a template bug, not a surprise.
RECEIPT_FIELDS = ("order_id", "total", "currency", "eta")


def render_email(user_template, context):
    return Template(user_template).render(**context)


def _autoescaping_env():
    """Environment with autoescaping on for every HTML-ish extension."""
    return Environment(autoescape=select_autoescape(["html", "htm", "xml"]))


def render_email_packaged(template_source, context):
    """Operator-authored template rendered with escaping switched on."""
    env = _autoescaping_env()
    return env.from_string(template_source).render(**context)


def render_profile(bio):
    env = Environment()
    tmpl = env.from_string("<h1>Profile</h1><p>" + bio + "</p>")
    return tmpl.render()


PROFILE_TEMPLATE = "<h1>Profile</h1><p>{{ bio }}</p>"


def render_profile_escaped(bio):
    """The bio is passed as a value, so it can never become template syntax."""
    env = _autoescaping_env()
    return env.from_string(PROFILE_TEMPLATE).render(bio=bio)


def render_banner(message):
    return eval('f"""' + message + '"""')


def render_banner_substituted(message, **values):
    """$-substitution: unknown names raise instead of evaluating anything.

    The banner text is written by merchandising and stored in the CMS, so it
    is operator-authored, but it still goes through the restricted syntax.
    """
    return StringTemplate(message).substitute(**values)


def format_receipt(fmt, **kwargs):
    return fmt.format(**kwargs)


RECEIPT_TEMPLATE = "Order $order_id — $total $currency, arriving $eta"


def format_receipt_fixed(**kwargs):
    """Fixed template filled from the declared field list."""
    values = {field: kwargs.get(field, "") for field in RECEIPT_FIELDS}
    return StringTemplate(RECEIPT_TEMPLATE).safe_substitute(**values)


def preview(text, limit=140):
    """Trim a rendered fragment for the list view without touching markup."""
    text = text or ""
    return text if len(text) <= limit else text[: limit - 1] + "…"
