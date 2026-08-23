"""Rendering of seller-facing notification bodies.

Two kinds of template are involved. The HTML shells are authored in this
repository and rendered by Jinja. The short subject lines are authored by the
marketing team in the back office, stored as rows, and expanded with a fixed
set of placeholders.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass
from typing import Any, Final, Mapping

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape
from markupsafe import Markup

# ---------------------------------------------------------------------------
# HTML bodies
# ---------------------------------------------------------------------------

_environment: Final = Environment(
    loader=PackageLoader("generation", "templates"),
    autoescape=select_autoescape(
        enabled_extensions=("html", "htm", "xml"),
        default_for_string=True,
        default=True,
    ),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)

# Fragments emitted verbatim in every notification body.
_SEPARATOR: Final = Markup('<hr style="border:0;border-top:1px solid #ddd">')
_BULLET: Final = Markup('<span aria-hidden="true">&bull;</span>')

_environment.globals["separator"] = _SEPARATOR
_environment.globals["bullet"] = _BULLET


def render_notification(template_name: str, **context: Any) -> str:
    """Renders one of the packaged notification templates.

    ``template_name`` names a file inside the package's template directory.
    """
    if not re.fullmatch(r"[a-z0-9_]{1,64}\.html", template_name):
        raise ValueError(f"not a packaged template: {template_name!r}")
    return _environment.get_template(template_name).render(**context)


# ---------------------------------------------------------------------------
# Subject lines
# ---------------------------------------------------------------------------

# The placeholders a stored subject line may use. Anything else is a mistake in
# the back office and is refused when the row is saved and again when it is
# rendered.
ALLOWED_PLACEHOLDERS: Final[frozenset[str]] = frozenset(
    {"seller_name", "listing_title", "artifact_count", "order_reference"}
)

MAX_SUBJECT_CHARS: Final = 200


class TemplateRejected(ValueError):
    """The stored template used a placeholder that is not permitted."""


@dataclass(frozen=True, slots=True)
class SubjectTemplate:
    """A validated subject-line template."""

    text: str

    @staticmethod
    def parse(raw: str) -> "SubjectTemplate":
        """Validates a stored template.

        Every field the template references must be a plain, named placeholder
        drawn from :data:`ALLOWED_PLACEHOLDERS`. Positional fields, attribute
        access, conversions and format specifications are refused.
        """
        if len(raw) > MAX_SUBJECT_CHARS:
            raise TemplateRejected("subject template is too long")

        for literal, field, spec, conversion in string.Formatter().parse(raw):
            del literal
            if field is None:
                continue
            if field == "" or not field.isidentifier():
                raise TemplateRejected(f"unsupported field reference: {field!r}")
            if field not in ALLOWED_PLACEHOLDERS:
                raise TemplateRejected(f"placeholder not permitted: {field!r}")
            if conversion is not None:
                raise TemplateRejected("conversions are not permitted")
            if spec:
                raise TemplateRejected("format specifications are not permitted")

        return SubjectTemplate(text=raw)

    def render(self, values: Mapping[str, object]) -> str:
        """Expands the template.

        The mapping supplies every permitted placeholder, so a template naming
        one the caller omitted renders it as an empty string.
        """
        supplied = {
            name: str(values.get(name, "")) for name in ALLOWED_PLACEHOLDERS
        }
        return self.text.format_map(supplied)[:MAX_SUBJECT_CHARS]
