"""Deployment helpers for Vast.ai and local execution."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class RemoteAsset:
    """Describes a file to download on the remote instance."""
    url: str
    filename: str          # downloaded filename
    output_name: str       # final filename after decompression
    decompress: Optional[str]  # gz | zip | 7z | bz2 | None
    remote_dir: str        # /root/wordlists or /root/rules


def render_onstart_script(
    hash_content: str,
    wordlist_assets: List[RemoteAsset],
    rule_assets: List[RemoteAsset],
    hashcat_command: str,
    output_file: str = "/root/cracked.txt",
    notification_cmd: Optional[str] = None,
) -> str:
    """Generate a self-contained Vast.ai onstart script.

    Downloads all wordlists and rules directly on the instance,
    handles decompression, then runs hashcat. Only the hash content
    is embedded inline — nothing needs uploading from the client.
    """
    lines = [
        "#!/bin/bash",
        "set -euo pipefail",
        "exec > /root/vastcat.log 2>&1",
        "",
        'echo "[vastcat] Starting at $(date)"',
        "",
        "# Install dependencies",
        "export DEBIAN_FRONTEND=noninteractive",
        "apt-get update -qq",
        "apt-get install -y -qq wget curl p7zip-full unzip build-essential git",
        "",
        "# Ensure hashcat is available",
        "if ! command -v hashcat &>/dev/null; then",
        "  echo '[vastcat] hashcat not found — installing from source'",
        "  cd /tmp",
        "  wget -q https://hashcat.net/files/hashcat-7.1.2.tar.gz -O hashcat.tar.gz",
        "  tar -xzf hashcat.tar.gz",
        "  cd hashcat-7.1.2",
        "  make -j$(nproc)",
        "  make install PREFIX=/usr/local",
        "  cd /",
        "fi",
        "",
        "mkdir -p /root/wordlists /root/rules",
        "",
        "# Write hash file inline",
        "cat > /root/hashes.txt << 'VASTCAT_HASH_EOF'",
        hash_content.rstrip(),
        "VASTCAT_HASH_EOF",
        "",
    ]

    # Wordlist downloads
    if wordlist_assets:
        lines.append("# Download wordlists")
        for asset in wordlist_assets:
            lines.extend(_download_block(asset))
        lines.append("")

    # Rule downloads
    if rule_assets:
        lines.append("# Download rules")
        for asset in rule_assets:
            lines.extend(_download_block(asset))
        lines.append("")

    lines += [
        'echo "[vastcat] All assets ready — launching hashcat"',
        "",
        hashcat_command,  # command already includes -o and --status flags
        "",
        'echo "[vastcat] Done at $(date)"',
        'echo "[vastcat] Cracked passwords:"',
        f"cat {output_file} 2>/dev/null || echo '(none)'",
    ]

    if notification_cmd:
        lines += ["", notification_cmd]

    return "\n".join(lines) + "\n"


def _download_block(asset: RemoteAsset) -> List[str]:
    """Return bash lines to download and decompress one asset."""
    dl_path = f"{asset.remote_dir}/{asset.filename}"
    out_path = f"{asset.remote_dir}/{asset.output_name}"
    lines = [f'echo "[vastcat] Downloading {asset.output_name}..."']

    if asset.decompress == "gz":
        lines += [
            f'wget -q "{asset.url}" -O "{dl_path}"',
            f'gunzip -f "{dl_path}"',
        ]
    elif asset.decompress == "zip":
        lines += [
            f'wget -q "{asset.url}" -O "{dl_path}"',
            f'unzip -q -o "{dl_path}" -d "{asset.remote_dir}/"',
            f'rm -f "{dl_path}"',
        ]
    elif asset.decompress == "bz2":
        lines += [
            f'wget -q "{asset.url}" -O "{dl_path}"',
            f'bunzip2 -f "{dl_path}"',
        ]
    elif asset.decompress == "7z":
        lines += [
            f'wget -q "{asset.url}" -O "{dl_path}"',
            f'7z x "{dl_path}" -o"{asset.remote_dir}/" -y',
            f'rm -f "{dl_path}"',
        ]
    else:
        lines.append(f'wget -q "{asset.url}" -O "{out_path}"')

    return lines


def remote_assets_from_keys(
    keys: List[str],
    remote_dir: str,
) -> List[RemoteAsset]:
    """Convert ASSET_LIBRARY keys to RemoteAsset descriptors."""
    from .assets import ASSET_LIBRARY
    assets = []
    for key in keys:
        a = ASSET_LIBRARY.get(key)
        if not a:
            continue
        filename = a.filename or Path(a.url).name
        output_name = a.output_name or filename
        # Strip compression extension for gz/bz2 to get final filename
        if a.decompress == "gz" and output_name.endswith(".gz"):
            output_name = output_name[:-3]
        elif a.decompress == "bz2" and output_name.endswith(".bz2"):
            output_name = output_name[:-4]
        assets.append(RemoteAsset(
            url=a.url,
            filename=filename,
            output_name=output_name,
            decompress=a.decompress,
            remote_dir=remote_dir,
        ))
    return assets


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


def render_startup_script(asset_paths) -> str:
    """Local script stub listing asset paths."""
    lines = ["#!/bin/bash", "# Asset paths:"]
    for p in asset_paths:
        lines.append(f"# {p}")
    return "\n".join(lines) + "\n"
