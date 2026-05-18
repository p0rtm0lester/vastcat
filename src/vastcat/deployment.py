"""Deployment helpers for Vast.ai and local execution."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Optional


def render_onstart_script(
    hash_content: str,
    wordlist_urls: List[str],
    rule_urls: List[str],
    hashcat_command: str,
    output_file: str = "/root/cracked.txt",
) -> str:
    """Generate a Vast.ai onstart script.

    Assumes the instance image already has hashcat installed (e.g. dizcza/docker-hashcat).
    Downloads wordlists/rules from URLs, writes the hash file inline, then runs hashcat.
    """
    wordlist_downloads = "\n".join(
        f'wget -q -P /root/wordlists/ "{url}"' for url in wordlist_urls
    )
    rule_downloads = "\n".join(
        f'wget -q -P /root/rules/ "{url}"' for url in rule_urls
    )

    # Escape hash content for embedding in heredoc
    safe_hash = hash_content.replace("'", "'\\''")

    return f"""#!/bin/bash
set -euo pipefail
exec > /root/vastcat.log 2>&1

echo "[vastcat] Starting at $(date)"

mkdir -p /root/wordlists /root/rules

# Write hash file
cat > /root/hashes.txt << 'HASHEOF'
{safe_hash}
HASHEOF

# Download wordlists
{wordlist_downloads if wordlist_downloads else "echo '[vastcat] No wordlists to download'"}

# Download rules
{rule_downloads if rule_downloads else "echo '[vastcat] No rules to download'"}

echo "[vastcat] Assets ready, launching hashcat"

{hashcat_command} -o {output_file} --status --status-timer=60

echo "[vastcat] Done at $(date)"
cat {output_file} 2>/dev/null || echo "[vastcat] No passwords cracked"
"""


def render_hashcat_command(
    hash_path: str,
    hash_mode: str,
    attack_mode: str,
    wordlists: List[str],
    rules: List[str],
    extra_args: str = "--status --status-timer=60",
    output_file: Optional[str] = None,
    workload: Optional[str] = None,
    mask: Optional[str] = None,
) -> str:
    """Build a hashcat command string.

    attack_mode semantics:
      0 = straight   — one wordlist + optional rules
      1 = combinator — two wordlists
      3 = mask       — mask string required, no wordlist
      6 = hybrid     — one wordlist + mask
    """
    from shlex import quote

    parts = ["hashcat", f"-m {hash_mode}", f"-a {attack_mode}"]

    if workload:
        parts.append(f"-w {workload}")

    if output_file:
        parts.append(f"-o {quote(output_file)}")

    if extra_args:
        parts.append(extra_args)

    parts.append(quote(hash_path))

    am = str(attack_mode)
    if am == "0":
        if wordlists:
            parts.append(quote(wordlists[0]))
        for rule in rules:
            parts.append(f"-r {quote(rule)}")
    elif am == "1":
        for wl in wordlists[:2]:
            parts.append(quote(wl))
    elif am == "3":
        if mask:
            parts.append(quote(mask))
    elif am == "6":
        if wordlists:
            parts.append(quote(wordlists[0]))
        if mask:
            parts.append(quote(mask))
        for rule in rules:
            parts.append(f"-r {quote(rule)}")
    else:
        for wl in wordlists:
            parts.append(quote(wl))
        for rule in rules:
            parts.append(f"-r {quote(rule)}")

    return " ".join(parts)


def render_startup_script(asset_paths: Iterable[Path]) -> str:
    """Legacy local startup script — lists asset paths for reference."""
    lines = ["#!/bin/bash", "# Asset paths for this vastcat job:"]
    for p in asset_paths:
        lines.append(f"# {p}")
    lines.append("")
    lines.append("# Run the generated hashcat command below:")
    return "\n".join(lines)
