#!/usr/bin/env python3
"""
ai-siem-triage: AI-powered SIEM alert triage assistant.
Ingests SIEM alerts (JSON or plain text) and provides AI-driven triage,
severity classification, false-positive assessment, and recommended response actions.
"""

import sys
import json
import click
from openai import OpenAI
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

client = OpenAI()
console = Console()


def load_alerts(source: str) -> str:
    """Load alert data from a file or stdin."""
    if source == "-":
        return sys.stdin.read()
    try:
        with open(source, "r") as f:
            content = f.read()
        # Try to pretty-print if JSON
        try:
            parsed = json.loads(content)
            return json.dumps(parsed, indent=2)
        except json.JSONDecodeError:
            return content
    except FileNotFoundError:
        console.print(f"[bold red]File not found:[/bold red] {source}")
        sys.exit(1)


@click.command()
@click.argument("source", default="-", metavar="FILE_OR_STDIN")
@click.option("--context", default=None, help="Additional environment context (e.g., 'AWS prod environment').")
@click.option("--rules", default=None, help="Path to custom detection rules file for context.")
def triage(source: str, context: str, rules: str):
    """Triage SIEM alerts from a file or stdin.

    Accepts JSON or plain-text alert data.

    Example:
        cat alerts.json | python main.py -
        python main.py alerts.json --context "Financial services prod"
    """
    alerts_data = load_alerts(source)
    if not alerts_data.strip():
        console.print("[bold red]No alert data provided.[/bold red]")
        sys.exit(1)

    rules_context = ""
    if rules:
        try:
            with open(rules, "r") as f:
                rules_context = f"\n\nCustom Detection Rules:\n{f.read()[:2000]}"
        except FileNotFoundError:
            console.print(f"[bold yellow]Warning: Rules file not found: {rules}[/bold yellow]")

    env_context = f"\nEnvironment Context: {context}" if context else ""
    console.print(Panel("[bold cyan]Triaging SIEM alerts...[/bold cyan]", expand=False))

    prompt = f"""You are a senior SOC (Security Operations Center) analyst. Triage the following SIEM alerts and provide:

1. **Alert Summary Table** – List each alert with: Alert Name | Severity | True/False Positive Likelihood | Priority
2. **Top Priority Incidents** – Detailed analysis of the highest-priority alerts.
3. **Attack Chain Analysis** – Are any alerts part of a coordinated attack chain?
4. **False Positive Assessment** – Which alerts are likely false positives and why?
5. **Immediate Response Actions** – Step-by-step actions for the top 3 priority alerts.
6. **Escalation Recommendation** – Should any alerts be escalated to IR?
{env_context}
{rules_context}

SIEM Alerts:
---
{alerts_data[:8000]}
---

Format your response in Markdown."""

    try:
        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": "You are an expert SOC analyst with deep experience in incident response, threat hunting, and SIEM platforms like Splunk, Elastic, and Microsoft Sentinel."},
                {"role": "user", "content": prompt}
            ]
        )
        console.print(Markdown(response.choices[0].message.content))
    except Exception as e:
        console.print(f"[bold red]AI analysis error:[/bold red] {e}")


if __name__ == "__main__":
    triage()
