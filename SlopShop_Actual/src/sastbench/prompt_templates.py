"""Prompt template management for orchestrated vulnerability analysis."""

from __future__ import annotations

from pathlib import Path

PROMPTS_DIR = Path(__file__).parent / "prompts"

BUILTIN_TEMPLATES = {
    "default": "default.txt",
    "thorough": "thorough.txt",
    "minimal": "minimal.txt",
    "selective": "selective.txt",
}


def get_prompt_template(name_or_path: str = "default") -> str:
    """Load a prompt template by name or file path.

    Args:
        name_or_path: Either a built-in template name ("default", "thorough",
            "minimal") or a path to a custom template file.

    Returns:
        The prompt template text.
    """
    # Check built-in templates
    if name_or_path in BUILTIN_TEMPLATES:
        template_path = PROMPTS_DIR / BUILTIN_TEMPLATES[name_or_path]
        return template_path.read_text(encoding="utf-8")

    # Try as file path
    p = Path(name_or_path)
    if p.exists():
        return p.read_text(encoding="utf-8")

    available = ", ".join(sorted(BUILTIN_TEMPLATES.keys()))
    raise ValueError(
        f"Unknown prompt template '{name_or_path}'. "
        f"Built-in templates: {available}. "
        f"Or pass a path to a custom .txt file."
    )


def list_prompt_templates() -> list[dict[str, str]]:
    """List all available built-in prompt templates."""
    templates = []
    for name, filename in sorted(BUILTIN_TEMPLATES.items()):
        path = PROMPTS_DIR / filename
        content = path.read_text(encoding="utf-8")
        first_line = content.strip().splitlines()[0] if content.strip() else ""
        templates.append({
            "name": name,
            "file": filename,
            "description": first_line,
            "length": len(content),
        })
    return templates
