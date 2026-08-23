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
