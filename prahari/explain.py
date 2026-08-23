"""Turn findings into something a human can act on.

The model never decides whether a boot is compromised -- the detector does that
from the measurement log. The model only explains findings that already exist,
so a hallucination cannot manufacture or suppress a detection. Explainability
is a scored criterion and this is the honest way to earn it.
"""
import os

PROMPT = """You are explaining Linux boot integrity findings to a system administrator.

Findings from comparing this boot against {boots} known-good boots:

{findings}

For each finding, in two sentences: what it means, and what to check next.
Be concrete. If a finding looks benign (a routine package update, for example),
say so plainly. Do not invent findings that are not listed above."""


def render(findings):
    return "\n".join(
        f"- [{f.severity}] {f.kind} at position {f.position}: {f.path} -- {f.detail}"
        for f in findings) or "- none"


def explain(findings, boots, model="claude-sonnet-5"):
    if not findings:
        return "Boot matches the learned baseline. No anomalies."
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return "Set ANTHROPIC_API_KEY for narrative explanations.\n\n" + render(findings)

    from anthropic import Anthropic

    message = Anthropic().messages.create(
        model=model,
        max_tokens=1024,
        messages=[{
            "role": "user",
            "content": PROMPT.format(boots=boots, findings=render(findings)),
        }],
    )
    return message.content[0].text
