
from jinja2 import Template, Environment
from string import Template as StringTemplate


def render_email(user_template, context):
    return Template(user_template).render(**context)


def render_profile(bio):
    env = Environment()
    tmpl = env.from_string("<h1>Profile</h1><p>" + bio + "</p>")
    return tmpl.render()


def render_banner(message):
    return eval('f"""' + message + '"""')


def format_receipt(fmt, **kwargs):
    return fmt.format(**kwargs)
