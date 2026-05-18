"""Deployment helpers for provisioning Ubuntu CUDA instances."""
from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from typing import Iterable, List, Optional

HASHCAT_URL = "https://hashcat.net/files/hashcat-7.1.2.tar.gz"


def render_startup_script(asset_paths: Iterable[Path], install_dir: str = "/opt/hashcat") -> str:
    files = " ".join(str(path) for path in asset_paths)
    return dedent(
        f"""
        #!/bin/bash
        set -euxo pipefail
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y build-essential wget curl p7zip-full git python3 python3-venv jq
        mkdir -p {install_dir}
        cd /tmp
        wget -q {HASHCAT_URL} -O hashcat.tar.gz
        tar -xzf hashcat.tar.gz
        rsync -a hashcat-*/* {install_dir}/
        ln -sf {install_dir}/hashcat /usr/local/bin/hashcat
        mkdir -p /opt/vastcat/assets
        # Placeholder for syncing assets that have been pre-fetched
        for file in {files}; do
            echo "$file" >> /opt/vastcat/assets/.manifest
        done
        echo "Vastcat bootstrap complete"
        """.strip()
    )


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
        # Straight: one wordlist only; multiple wordlists must be pre-concatenated
        if wordlists:
            parts.append(quote(wordlists[0]))
        for rule in rules:
            parts.append(f"-r {quote(rule)}")
    elif am == "1":
        # Combinator: exactly two wordlists
        for wl in wordlists[:2]:
            parts.append(quote(wl))
    elif am == "3":
        # Mask/brute-force: no wordlist, mask is a positional arg
        if mask:
            parts.append(quote(mask))
    elif am == "6":
        # Hybrid wordlist + mask
        if wordlists:
            parts.append(quote(wordlists[0]))
        if mask:
            parts.append(quote(mask))
        for rule in rules:
            parts.append(f"-r {quote(rule)}")
    else:
        # Fallback: pass everything
        for wl in wordlists:
            parts.append(quote(wl))
        for rule in rules:
            parts.append(f"-r {quote(rule)}")

    return " ".join(parts)
