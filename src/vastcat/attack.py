"""Automated hashcat attack chain for vastcat.

Encodes the escalation strategy learned from real engagements:
  1. Identify hash mode from file sample
  2. Fast straight attacks with quality wordlists + rules
  3. Escalate to larger wordlists (CrackStation)
  4. Hybrid attacks (word + digit/special masks, both directions)
  5. Brute force for short passwords

Each phase checks for cracks before proceeding to the next.
Designed to run inside a Vast.ai onstart script or directly via SSH.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Phase:
    name: str
    mode: int           # hashcat -a mode
    wordlists: List[str]
    rules: List[str] = field(default_factory=list)
    mask: Optional[str] = None
    note: str = ""

    def hashcat_args(self, hash_path: str, output: str, hash_mode: int, workload: int = 3) -> str:
        """Build the hashcat command for this phase."""
        from shlex import quote
        parts = [
            "hashcat",
            f"-m {hash_mode}",
            f"-a {self.mode}",
            f"-w {workload}",
            "-O",
            "--status --status-timer=30",
            f"-o {quote(output)}",
            quote(hash_path),
        ]
        if self.mode == 0:          # straight
            parts.append(quote(self.wordlists[0]))
            for r in self.rules:
                parts.append(f"-r {quote(r)}")
        elif self.mode == 1:        # combinator
            for wl in self.wordlists[:2]:
                parts.append(quote(wl))
        elif self.mode == 6:        # hybrid word+mask
            parts.append(quote(self.wordlists[0]))
            parts.append(quote(self.mask or "?d?d?d?d"))
            for r in self.rules:
                parts.append(f"-r {quote(r)}")
        elif self.mode == 7:        # hybrid mask+word
            parts.append(quote(self.mask or "?d?d?d?d"))
            parts.append(quote(self.wordlists[0]))
        elif self.mode == 3:        # brute-force
            parts.append(quote(self.mask or "?a?a?a?a?a?a?a"))
        return " ".join(parts)


# Remote paths used inside Vast.ai instances
REMOTE = {
    "rockyou":      "/root/wordlists/rockyou.txt",
    "crackstation": "/root/wordlists/crackstation-human.txt",
    "combined":     "/root/wordlists/combined.txt",
    "d3ad0ne":      "/root/rules/d3ad0ne.rule",
    "onerule":      "/root/rules/onerule.rule",
    "rockyou30k":   "/root/rules/rockyou30k.rule",
}

# ---------------------------------------------------------------------------
# Standard attack chain — ordered by speed vs coverage trade-off.
# Build the combined wordlist on the instance before running these.
# ---------------------------------------------------------------------------
STANDARD_CHAIN: List[Phase] = [

    # ── Phase 1: Fast straight with quality rules ──────────────────────────
    # rockyou + d3ad0ne covers ~946B candidates in seconds at high GH/s.
    Phase(
        name="rockyou + d3ad0ne",
        mode=0,
        wordlists=[REMOTE["rockyou"]],
        rules=[REMOTE["d3ad0ne"]],
        note="First pass — fast, covers most common passwords with mutations",
    ),

    # ── Phase 2: Larger wordlist ───────────────────────────────────────────
    # CrackStation human-only (64M) catches passwords not in rockyou
    # (breach-specific, country-specific, older passwords like mikes.411)
    Phase(
        name="CrackStation human + d3ad0ne",
        mode=0,
        wordlists=[REMOTE["combined"]],   # rockyou + crackstation merged
        rules=[REMOTE["d3ad0ne"]],
        note="Second pass — 78M words covers breach-specific passwords",
    ),

    # ── Phase 3: Deeper rules ──────────────────────────────────────────────
    # OneRuleToRuleThemStill (48K rules) catches complex mutations
    Phase(
        name="combined + OneRuleToRuleThemStill",
        mode=0,
        wordlists=[REMOTE["combined"]],
        rules=[REMOTE["onerule"]],
        note="Third pass — 48K rules, catches l33t/complex mutations",
    ),

    # ── Phase 4: Hybrid word + year/digits ────────────────────────────────
    # Very common pattern: password2005, admin123, letmein!
    Phase(name="combined + ?d?d?d?d",   mode=6, wordlists=[REMOTE["combined"]], mask="?d?d?d?d",
          note="word+4digits e.g. password2005"),
    Phase(name="combined + ?d?d",       mode=6, wordlists=[REMOTE["combined"]], mask="?d?d"),
    Phase(name="combined + ?d?d?d",     mode=6, wordlists=[REMOTE["combined"]], mask="?d?d?d"),
    Phase(name="combined + ?d?d?d?d?d", mode=6, wordlists=[REMOTE["combined"]], mask="?d?d?d?d?d"),

    # ── Phase 5: Hybrid word + special ────────────────────────────────────
    Phase(name="combined + ?s",         mode=6, wordlists=[REMOTE["combined"]], mask="?s",
          note="word+symbol e.g. password!"),
    Phase(name="combined + ?s?d?d?d?d", mode=6, wordlists=[REMOTE["combined"]], mask="?s?d?d?d?d"),
    Phase(name="combined + ?d?d?d?d?s", mode=6, wordlists=[REMOTE["combined"]], mask="?d?d?d?d?s"),

    # ── Phase 6: Hybrid reversed (digits/special prefix) ──────────────────
    Phase(name="?d?d?d?d + combined",   mode=7, wordlists=[REMOTE["combined"]], mask="?d?d?d?d"),
    Phase(name="?d?d + combined",       mode=7, wordlists=[REMOTE["combined"]], mask="?d?d"),
    Phase(name="?s + combined",         mode=7, wordlists=[REMOTE["combined"]], mask="?s"),

    # ── Phase 7: Brute force short passwords ──────────────────────────────
    Phase(name="brute lower 6",         mode=3, wordlists=[], mask="?l?l?l?l?l?l"),
    Phase(name="brute lower 7",         mode=3, wordlists=[], mask="?l?l?l?l?l?l?l"),
    Phase(name="brute lower 8",         mode=3, wordlists=[], mask="?l?l?l?l?l?l?l?l"),
    Phase(name="brute lower+digit 7",   mode=3, wordlists=[], mask="?h?h?h?h?h?h?h"),
    Phase(name="brute all-print 6",     mode=3, wordlists=[], mask="?a?a?a?a?a?a"),
    Phase(name="brute all-print 7",     mode=3, wordlists=[], mask="?a?a?a?a?a?a?a"),
]

# Full CrackStation (1.49B) — expensive but comprehensive
EXTENDED_CHAIN: List[Phase] = [
    Phase(
        name="CrackStation full + d3ad0ne",
        mode=0,
        wordlists=["/root/wordlists/crackstation-full.txt"],
        rules=[REMOTE["d3ad0ne"]],
        note="1.49B passwords — catches rare/old passwords missed by smaller lists",
    ),
    Phase(
        name="CrackStation full + onerule",
        mode=0,
        wordlists=["/root/wordlists/crackstation-full.txt"],
        rules=[REMOTE["onerule"]],
    ),
    Phase(name="crackstation-full + ?d?d?d?d", mode=6,
          wordlists=["/root/wordlists/crackstation-full.txt"], mask="?d?d?d?d"),
    Phase(name="brute all-print 8", mode=3, wordlists=[], mask="?a?a?a?a?a?a?a?a",
          note="~7hrs at 20GH/s — last resort"),
]


def render_attack_script(
    hash_path: str,
    hash_mode: int,
    output_path: str,
    total_hashes: int,
    phases: List[Phase],
    workload: int = 3,
    wordlist_downloads: Optional[str] = None,
) -> str:
    """Generate a self-contained bash script that runs the attack chain."""
    lines = [
        "#!/bin/bash",
        "export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH",
        f"TOTAL={total_hashes}",
        f"OUT={output_path}",
        "",
        "all_cracked() {",
        '  [ "$(wc -l < $OUT 2>/dev/null || echo 0)" -ge "$TOTAL" ]',
        "}",
        "",
    ]

    if wordlist_downloads:
        lines += [wordlist_downloads, ""]

    for phase in phases:
        cmd = phase.hashcat_args(hash_path, output_path, hash_mode, workload)
        lines += [
            f'echo ">>> {phase.name}"',
            cmd,
            "all_cracked && { echo ALL_CRACKED; cat $OUT; exit 0; }",
            "",
        ]

    lines += [
        'echo "ALL_DONE"',
        "cat $OUT 2>/dev/null || echo '(none cracked)'",
    ]
    return "\n".join(lines) + "\n"
