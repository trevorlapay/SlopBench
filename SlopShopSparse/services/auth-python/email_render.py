"""Transactional email rendering with autoescaping enabled (safe by default)."""
from jinja2 import Environment, select_autoescape

_env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))

_ORDER_CONFIRMATION = _env.from_string(
    "<h1>Thanks, {{ name }}</h1>"
    "<p>Order #{{ order_id }} totalling {{ total }} is confirmed.</p>"
    "<ul>{% for line in lines %}<li>{{ line.name }} x{{ line.qty }}</li>{% endfor %}</ul>"
)

_SHIPPING_NOTICE = _env.from_string(
    "<p>Hi {{ name }}, order #{{ order_id }} shipped via {{ carrier }}.</p>"
    "<p>Tracking: {{ tracking }}</p>"
)


def order_confirmation(name, order_id, total, lines) -> str:
    return _ORDER_CONFIRMATION.render(name=name, order_id=order_id, total=total, lines=lines)


def shipping_notice(name, order_id, carrier, tracking) -> str:
    return _SHIPPING_NOTICE.render(name=name, order_id=order_id, carrier=carrier, tracking=tracking)


def plain_text(html: str) -> str:
    out, in_tag = [], False
    for ch in html:
        if ch == "<":
            in_tag = True
        elif ch == ">":
            in_tag = False
        elif not in_tag:
            out.append(ch)
    return "".join(out).strip()
_PASSWORD_RESET = _env.from_string(
    "<p>Hi {{ name }}, a password reset was requested for your account.</p>"
    "<p><a href=\"{{ link }}\">Reset your password</a></p>"
    "<p>If this was not you, no action is needed.</p>"
)

_REFUND_NOTICE = _env.from_string(
    "<p>Hi {{ name }}, your refund of {{ amount }} for order #{{ order_id }} "
    "has been issued and should appear within {{ days }} business days.</p>"
)


def password_reset(name, link) -> str:
    return _PASSWORD_RESET.render(name=name, link=link)


def refund_notice(name, order_id, amount, days=5) -> str:
    return _REFUND_NOTICE.render(name=name, order_id=order_id, amount=amount, days=days)


def subject_for(kind: str) -> str:
    """Subject line for a transactional message kind."""
    subjects = {
        "order_confirmation": "Your SlopShop order is confirmed",
        "shipping_notice": "Your SlopShop order has shipped",
        "password_reset": "Reset your SlopShop password",
        "refund_notice": "Your SlopShop refund has been issued",
    }
    if kind not in subjects:
        raise KeyError("no subject for message kind: %s" % kind)
    return subjects[kind]
