"""Interactive wizard for Vastcat."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional
import os
import shlex

from rich.console import Console
import questionary
from questionary import Choice

from .assets import ASSET_LIBRARY, AssetManager, list_assets
from .config import ensure_config
from .deployment import (
    remote_assets_from_keys,
    render_hashcat_command,
    render_onstart_script,
    render_startup_script,
)
from .detect import HashGuess, detect_hash_modes, sample_from_file
from .hashcat import HashcatRunner
from .notifier import Notifier
from .theme import CAT_ASCII, cat_say


ATTACK_MODES = {
    "Straight (mode 0) — wordlist + rules": "0",
    "Combinator (mode 1) — two wordlists combined": "1",
    "Mask / Brute-force (mode 3) — pattern only": "3",
    "Hybrid Wordlist + Mask (mode 6) — wordlist prepended to mask": "6",
}

WORKLOAD_PROFILES = {
    "1 — Low (background, won't impact system)": "1",
    "2 — Default (balanced)": "2",
    "3 — High (recommended for dedicated cracking rigs)": "3",
    "4 — Nightmare (max, may freeze desktop)": "4",
}


class Wizard:
    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()
        self.config = ensure_config()
        self.asset_manager = AssetManager(self.config)

    def run(self) -> None:
        self.console.print(CAT_ASCII)
        self.console.print(cat_say("Welcome to Vastcat's wizard."))

        # Collect all configuration
        config = self._collect_configuration()
        if not config:
            return

        # Review and edit loop
        while True:
            self._show_configuration_summary(config)

            action = questionary.select(
                "What would you like to do?",
                choices=[
                    "Proceed with these settings",
                    "Edit a parameter",
                    "Start over",
                    "Cancel"
                ]
            ).ask()

            if action == "Proceed with these settings":
                break
            elif action == "Edit a parameter":
                if not self._edit_configuration(config):
                    continue
            elif action == "Start over":
                config = self._collect_configuration()
                if not config:
                    return
            else:  # Cancel
                self.console.print(cat_say("Wizard cancelled."))
                return

        # Generate command and proceed
        self._execute_configuration(config)

    def _collect_configuration(self) -> Optional[dict]:
        """Collect all configuration parameters with corrected step order."""
        config = {}

        # Steps ordered logically: know what you're cracking before picking wordlists
        steps = [
            ("Specify Hash File", self._step_get_hash_file),
            ("Detect Hash Mode", self._step_determine_hash_mode),
            ("Choose Attack Mode", self._step_choose_attack_mode),
            ("Select Wordlists", self._step_select_wordlists),
            ("Select Rules", self._step_select_rules),
            ("Output & Options", self._step_output_options),
            ("Configure Notifications", self._step_configure_webhook),
            ("Deploy to Vast.ai", self._step_vast_deploy),
        ]

        current_step = 0
        while current_step < len(steps):
            step_name, step_func = steps[current_step]
            self.console.print(f"\n[bold cyan]Step {current_step + 1}/{len(steps)}: {step_name}[/bold cyan]")

            result = step_func(config, can_go_back=(current_step > 0))

            if result == "back":
                current_step -= 1
            elif result == "cancel":
                self.console.print(cat_say("Wizard cancelled."))
                return None
            elif result == "next":
                current_step += 1
            else:
                current_step += 1

        return config

    def _step_get_hash_file(self, config: dict, can_go_back: bool) -> str:
        """Step 1: Get hash file path."""
        hashes_dir = self.config.hashes_dir
        self.console.print(cat_say(f"Default hash directory: {hashes_dir}"))
        default_hash_path = str(hashes_dir / "hash.txt")

        while True:
            prompt_text = "Path to your hash file (or 'back')" if can_go_back else "Path to your hash file"
            hash_path = questionary.text(prompt_text, default=default_hash_path).ask()

            if hash_path and hash_path.lower() == "back" and can_go_back:
                return "back"

            expanded_path = Path(hash_path).expanduser()
            if expanded_path.exists():
                config['hash_path'] = str(expanded_path)
                # Show sample so user can verify
                from .detect import sample_from_file
                sample = sample_from_file(str(expanded_path))
                if sample:
                    self.console.print(f"[dim]Sample: {sample[:64]}[/dim]")
                return "next"

            self.console.print(f"[red]File not found:[/red] {expanded_path}")
            if not questionary.confirm("Try another path?", default=True).ask():
                if can_go_back and questionary.confirm("Go back?", default=False).ask():
                    return "back"
                return "cancel"

    def _step_determine_hash_mode(self, config: dict, can_go_back: bool) -> str:
        """Step 2: Determine hash mode."""
        hash_mode = self._determine_hash_mode_with_back(config['hash_path'], can_go_back)
        if hash_mode == "back":
            return "back"
        if hash_mode == "cancel":
            return "cancel"
        config['hash_mode'] = hash_mode
        return "next"

    def _step_choose_attack_mode(self, config: dict, can_go_back: bool) -> str:
        """Step 3: Choose attack mode. Gate on what makes sense for the hash type."""
        choices = list(ATTACK_MODES.keys())
        if can_go_back:
            choices.append("← Go back")

        attack_choice = questionary.select("Choose attack mode", choices=choices).ask()
        if attack_choice == "← Go back":
            return "back"

        config['attack_mode'] = ATTACK_MODES[attack_choice]
        config['attack_choice'] = attack_choice

        # For mask-based modes, collect the mask pattern now
        if config['attack_mode'] in ("3", "6"):
            result = self._step_get_mask(config, can_go_back=True)
            if result != "next":
                return result

        return "next"

    def _step_get_mask(self, config: dict, can_go_back: bool) -> str:
        """Collect mask pattern for attack modes 3 and 6."""
        self.console.print(cat_say(
            "Mask syntax: ?l=lower ?u=upper ?d=digit ?s=symbol ?a=all\n"
            "  Examples: ?u?l?l?l?d?d?d?d  (8-char: Cap+3lower+4digits)\n"
            "            ?a?a?a?a?a?a?a?a  (8-char: any)\n"
            "            Password?d?d?d?d  (literal prefix + 4 digits)"
        ))
        while True:
            mask = questionary.text("Enter mask pattern (or 'back')").ask()
            if mask and mask.lower() == "back":
                return "back"
            if mask and mask.strip():
                config['mask'] = mask.strip()
                return "next"
            self.console.print("[red]Mask cannot be empty.[/red]")

    def _step_select_wordlists(self, config: dict, can_go_back: bool) -> str:
        """Step 4: Select wordlists. Skipped for pure mask attack (mode 3)."""
        attack_mode = config.get('attack_mode', '0')

        if attack_mode == "3":
            config['wordlist_keys'] = []
            return "next"

        need_two = (attack_mode == "1")
        if need_two:
            self.console.print(cat_say("Combinator mode needs exactly two wordlists. They will be combined pairwise."))

        while True:
            wordlist_keys = self._pick_assets_with_back("wordlists", can_go_back)
            if wordlist_keys == "back":
                return "back"
            if wordlist_keys == "cancel":
                return "cancel"
            if not wordlist_keys:
                self.console.print(cat_say("No wordlists selected. At least one is required."))
                if questionary.confirm("Try again?", default=True).ask():
                    continue
                return "cancel"
            if need_two and len(wordlist_keys) < 2:
                self.console.print(cat_say("Combinator mode requires two wordlists. Please select at least two."))
                if questionary.confirm("Try again?", default=True).ask():
                    continue
                return "cancel"
            break

        self.asset_manager.sync(wordlist_keys)
        failed = getattr(self.asset_manager, 'errors', {})
        for key, err in failed.items():
            self.console.print(f"[yellow]⚠  {key}:[/yellow] {err}")
        succeeded = [k for k in wordlist_keys if k not in failed]
        if not succeeded:
            self.console.print(cat_say("All wordlist downloads failed."))
            if questionary.confirm("Try again?", default=True).ask():
                return self._step_select_wordlists(config, can_go_back)
            return "cancel"
        if failed:
            self.console.print(f"[yellow]Continuing with {len(succeeded)}/{len(wordlist_keys)} wordlists.[/yellow]")
        if need_two and len(succeeded) < 2:
            self.console.print(cat_say("Need two working wordlists for combinator mode. Please try again."))
            if questionary.confirm("Try again?", default=True).ask():
                return self._step_select_wordlists(config, can_go_back)
            return "cancel"

        # Warn if multiple selected for straight mode
        if attack_mode == "0" and len(succeeded) > 1:
            self.console.print(
                f"[yellow]Note:[/yellow] Straight mode uses one wordlist at a time. "
                f"Only [bold]{succeeded[0]}[/bold] will be used. "
                "To use multiple, concatenate them first."
            )

        config['wordlist_keys'] = succeeded
        return "next"

    def _step_select_rules(self, config: dict, can_go_back: bool) -> str:
        """Step 5: Select rules. Only applicable for modes 0 and 6."""
        attack_mode = config.get('attack_mode', '0')

        if attack_mode in ("1", "3"):
            config['rule_keys'] = []
            return "next"

        self.console.print(cat_say("Rules multiply wordlist coverage — highly recommended for straight attacks."))
        rule_keys = self._pick_assets_with_back("rules", can_go_back)

        if rule_keys == "back":
            return "back"
        if rule_keys == "cancel":
            return "cancel"
        if not rule_keys:
            self.console.print(cat_say("No rules — proceeding with straight wordlist attack."))
        else:
            self.asset_manager.sync(rule_keys)
            failed = getattr(self.asset_manager, 'errors', {})
            for key, err in failed.items():
                self.console.print(f"[yellow]⚠  {key}:[/yellow] {err}")
            rule_keys = [k for k in rule_keys if k not in failed]
            if failed and rule_keys:
                self.console.print(f"[yellow]Continuing with {len(rule_keys)} rule(s).[/yellow]")

        config['rule_keys'] = rule_keys if isinstance(rule_keys, list) else []
        return "next"

    def _step_output_options(self, config: dict, can_go_back: bool) -> str:
        """Step 6: Output file, workload profile, extra flags."""
        choices = list(WORKLOAD_PROFILES.keys())
        if can_go_back:
            choices.append("← Go back")

        workload_choice = questionary.select(
            "Workload profile (affects GPU/CPU usage)",
            choices=choices,
            default=choices[1],  # Default
        ).ask()
        if workload_choice == "← Go back":
            return "back"
        config['workload'] = WORKLOAD_PROFILES[workload_choice]

        output_path = questionary.text(
            "Output file for cracked passwords (leave blank to skip)",
            default="",
        ).ask()
        config['output_file'] = output_path.strip() or None

        # Offer --show to dump already-cracked hashes from potfile
        if questionary.confirm("Check potfile for already-cracked hashes before running?", default=True).ask():
            config['show_potfile'] = True
        else:
            config['show_potfile'] = False

        return "next"

    def _step_configure_webhook(self, config: dict, can_go_back: bool) -> str:
        """Step 7: Configure notifications."""
        self.console.print(cat_say("Get notified when cracking finishes. All fields optional."))

        if can_go_back and questionary.confirm("Skip notifications?", default=True).ask():
            config['webhook'] = None
            config['slack_webhook'] = None
            config['pushover_token'] = None
            config['pushover_user'] = None
            return "next"

        default_discord = self.config.get("discord_webhook") or ""
        discord = questionary.text("Discord webhook URL (blank to skip)", default=default_discord).ask()
        if discord and discord.lower() == "back" and can_go_back:
            return "back"
        if discord:
            self.config.set("discord_webhook", discord)

        slack = questionary.text("Slack webhook URL (blank to skip)", default="").ask()
        if slack:
            self.config.set("slack_webhook", slack)

        pushover_token = questionary.text("Pushover app token (blank to skip)", default=self.config.get("pushover_token") or "").ask()
        pushover_user = ""
        if pushover_token:
            pushover_user = questionary.text("Pushover user key", default=self.config.get("pushover_user") or "").ask()
            if pushover_token:
                self.config.set("pushover_token", pushover_token)
            if pushover_user:
                self.config.set("pushover_user", pushover_user)

        config['webhook'] = discord or None
        config['slack_webhook'] = slack or None
        config['pushover_token'] = pushover_token or None
        config['pushover_user'] = pushover_user or None
        return "next"

    # Known Docker images that have hashcat pre-installed
    HASHCAT_IMAGES = [
        "dizcza/docker-hashcat:latest",
        "dizcza/docker-hashcat:cuda11.7",
        "nvidia/cuda:12.2.0-runtime-ubuntu22.04",  # base, hashcat not included
    ]

    def _step_vast_deploy(self, config: dict, can_go_back: bool) -> str:
        """Step 8: Optionally deploy to Vast.ai."""
        choices = ["Deploy to Vast.ai", "Run locally / generate script only"]
        if can_go_back:
            choices.append("← Go back")
        choice = questionary.select("Where do you want to run hashcat?", choices=choices).ask()

        if choice == "← Go back":
            return "back"

        config['vast_deploy'] = (choice == "Deploy to Vast.ai")
        if not config['vast_deploy']:
            return "next"

        # API key
        saved_key = self.config.get("vast_api_key") or ""
        api_key = questionary.text("Vast.ai API key", default=saved_key).ask()
        if not api_key or not api_key.strip():
            self.console.print("[red]API key required.[/red]")
            config['vast_deploy'] = False
            return "next"
        api_key = api_key.strip()
        self.config.set("vast_api_key", api_key)
        config['vast_api_key'] = api_key

        # Docker image / template
        saved_image = self.config.get("vast_image") or self.HASHCAT_IMAGES[0]
        image_choices = self.HASHCAT_IMAGES.copy()
        if saved_image not in image_choices:
            image_choices.insert(0, saved_image)
        image_choices.append("Enter custom image...")

        img_choice = questionary.select(
            "Docker image (choose a hashcat template or enter custom)",
            choices=image_choices,
            default=saved_image if saved_image in image_choices else image_choices[0],
        ).ask()

        if img_choice == "Enter custom image...":
            img_choice = questionary.text("Docker image", default=saved_image).ask()

        config['vast_image'] = img_choice or self.HASHCAT_IMAGES[0]
        self.config.set("vast_image", config['vast_image'])

        # GPU filters
        max_price = questionary.text("Max price per hour (USD)", default="0.50").ask()
        min_vram  = questionary.text("Min GPU VRAM (GB)", default="8").ask()
        disk_gb   = questionary.text("Disk space (GB)", default=str(self.config.get("vast_disk_gb", 20))).ask()
        try:
            config['vast_max_price'] = float(max_price)
            config['vast_min_vram']  = float(min_vram)
            config['vast_disk_gb']   = int(disk_gb)
        except ValueError:
            config['vast_max_price'] = 0.50
            config['vast_min_vram']  = 8.0
            config['vast_disk_gb']   = 20
        self.config.set("vast_disk_gb", config['vast_disk_gb'])

        # Search offers ranked by efficiency for the actual hash mode being cracked
        hash_mode = config.get('hash_mode', '1000')
        mode_name = {
            "1000": "NTLM", "5600": "NetNTLMv2", "5500": "NetNTLMv1",
            "300": "MySQL4.1", "0": "MD5", "100": "SHA-1",
            "1400": "SHA-256", "3200": "bcrypt", "13100": "Kerberos TGS",
            "18200": "Kerberos AS-REP", "22000": "WPA2",
        }.get(str(hash_mode), f"mode {hash_mode}")

        self.console.print(cat_say(f"Searching Vast.ai — ranking by efficiency for {mode_name}..."))
        try:
            from .vast import VastClient
            client = VastClient(api_key)
            offers = client.search_offers(
                min_vram_gb=config['vast_min_vram'],
                max_hourly=config['vast_max_price'],
                hash_mode=str(hash_mode),
                top_n=10,
            )
        except Exception as exc:
            self.console.print(f"[red]Vast.ai search failed:[/red] {exc}")
            config['vast_deploy'] = False
            return "next"

        if not offers:
            self.console.print(cat_say("No offers found. Try raising max price or lowering VRAM."))
            config['vast_deploy'] = False
            return "next"

        best_eff = max((o.efficiency(str(hash_mode)) for o in offers), default=0.0)
        offer_choices = [o.display(best_efficiency=best_eff, hash_mode=str(hash_mode)) for o in offers]
        offer_choices.append("← Cancel Vast.ai deployment")

        self.console.print(f"\n[dim]  Badge   GPU                  VRAM  CUDA    Price      Speed ({mode_name})        Uptime[/dim]")
        selected = questionary.select("Select a GPU instance", choices=offer_choices).ask()

        if selected == "← Cancel Vast.ai deployment":
            config['vast_deploy'] = False
            return "next"

        selected_offer = offers[offer_choices.index(selected)]
        config['vast_offer'] = selected_offer
        self.console.print(f"[green]✓[/green] Selected: {selected_offer.display()}")

        return "next"

    def _pick_assets_with_back(self, category: str, can_go_back: bool):
        """Pick assets with back navigation support. Cached assets are marked."""
        keys = list_assets(category)
        if not keys:
            return []

        self.console.print(f"\n[bold]Available {category}:[/bold] [dim]([green]●[/green] = already cached)[/dim]")

        if category == "rules":
            self.console.print(f"  [cyan]0[/cyan]. No rules (straight wordlist attack)")

        for idx, key in enumerate(keys, 1):
            asset = ASSET_LIBRARY[key]
            cached = self.asset_manager._output_path(asset).exists()
            marker = "[green]●[/green] " if cached else "  "
            self.console.print(f"  {marker}[cyan]{idx}[/cyan]. {key}: [dim]{asset.description}[/dim]")

        self.console.print(f"\n[bold]Enter numbers to select {category}:[/bold]")
        if category == "rules":
            examples = "'0' (none), '1', '1,2', '1-3', 'all'"
        else:
            examples = "'1', '1,2', '1-3', 'all'"
        if can_go_back:
            examples += ", 'back'"
        self.console.print(f"[dim]{examples}[/dim]")

        selection = questionary.text(
            f"Select {category}",
            default="all" if category == "wordlists" else ""
        ).ask()

        if not selection or selection.strip() == "":
            return []
        if selection.strip().lower() == "back" and can_go_back:
            return "back"
        if category == "rules" and selection.strip() == "0":
            self.console.print(f"[green]✓[/green] No rules")
            return []

        try:
            selected_indices = self._parse_selection(selection.strip(), len(keys))
            selected_keys = [keys[i] for i in selected_indices]
            if selected_keys:
                self.console.print(f"[green]✓[/green] Selected {len(selected_keys)} {category}: {', '.join(selected_keys)}")
            return selected_keys
        except ValueError as e:
            self.console.print(f"[red]Invalid selection:[/red] {e}")
            return []

    def _prompt_discord_with_back(self, can_go_back: bool):
        """Prompt for Discord webhook with back navigation support."""
        default = self.config.get("discord_webhook")
        prompt_text = "Discord webhook (optional, or 'back' to go back)" if can_go_back else "Discord webhook (optional)"
        webhook = questionary.text(prompt_text, default=default or "").ask()

        if webhook and webhook.lower() == "back" and can_go_back:
            return "back"

        if webhook:
            self.config.set("discord_webhook", webhook)

        return webhook

    def _determine_hash_mode_with_back(self, hash_path: str, can_go_back: bool):
        """Determine hash mode with back navigation support."""
        sample = sample_from_file(hash_path)
        if not sample:
            self.console.print(cat_say("Could not read a hash sample; please enter the mode manually."))
            return self._manual_hash_mode()

        guesses = detect_hash_modes(sample)
        if not guesses:
            self.console.print(cat_say("No matching hash types detected. Falling back to manual entry."))
            return self._manual_hash_mode()

        self.console.print(cat_say(f"Sample hash snippet: {sample[:24]}..."))
        choices = [
            Choice(
                title=f"{guess.name} (mode {guess.mode}) — {guess.reason}",
                value=guess.mode,
            )
            for guess in guesses
        ]
        choices.append(Choice(title="Enter manually", value="__manual__"))

        if can_go_back:
            choices.append(Choice(title="← Go back", value="__back__"))

        selection = questionary.select(
            "Detected hash types (confirm or pick manually)",
            choices=choices,
        ).ask()

        if selection == "__back__":
            return "back"
        elif selection == "__manual__":
            return self._manual_hash_mode()

        chosen = self._guess_from_mode(guesses, selection)
        if chosen:
            self.console.print(cat_say(f"Using {chosen.name} (mode {chosen.mode})."))
        return selection

    def _show_configuration_summary(self, config: dict) -> None:
        """Display current configuration to user."""
        wordlist_paths = self.asset_manager.resolved_paths(config.get('wordlist_keys', []))
        rule_paths = self.asset_manager.resolved_paths(config.get('rule_keys', []))

        self.console.rule(cat_say("Configuration Summary"))
        self.console.print(f"[bold]Hash file:[/bold]    {config.get('hash_path')}")
        self.console.print(f"[bold]Hash mode:[/bold]    {config.get('hash_mode')}")
        self.console.print(f"[bold]Attack mode:[/bold]  {config.get('attack_choice')}")
        if config.get('mask'):
            self.console.print(f"[bold]Mask:[/bold]         {config['mask']}")
        if wordlist_paths:
            self.console.print(f"[bold]Wordlists:[/bold]    {', '.join(p.name for p in wordlist_paths)}")
        if rule_paths:
            self.console.print(f"[bold]Rules:[/bold]        {', '.join(p.name for p in rule_paths)}")
        else:
            self.console.print(f"[bold]Rules:[/bold]        None")
        self.console.print(f"[bold]Workload:[/bold]     -{config.get('workload', '2')} ({['','Low','Default','High','Nightmare'][int(config.get('workload','2'))]})")
        self.console.print(f"[bold]Output file:[/bold]  {config.get('output_file') or 'None (use potfile)'}")
        notifs = [k for k in ('webhook', 'slack_webhook', 'pushover_token') if config.get(k)]
        self.console.print(f"[bold]Notifications:[/bold] {', '.join(notifs) or 'None'}\n")

    def _edit_configuration(self, config: dict) -> bool:
        """Allow user to edit a specific parameter. Returns True if edit was made."""
        edit_choices = [
            "1. Hash file path",
            "2. Hash mode",
            "3. Attack mode",
            "4. Wordlists",
            "5. Rules",
            "6. Discord webhook",
            "Back to summary"
        ]

        choice = questionary.select("Which parameter would you like to edit?", choices=edit_choices).ask()

        if choice == "Back to summary":
            return False
        elif choice.startswith("1"):
            # Edit hash file
            while True:
                hash_path = questionary.text("Path to your hash file", default=config['hash_path']).ask()
                expanded_path = Path(hash_path).expanduser()
                if expanded_path.exists():
                    config['hash_path'] = hash_path
                    # Re-detect hash mode
                    config['hash_mode'] = self._determine_hash_mode(hash_path)
                    break
                self.console.print(cat_say(f"File not found: {expanded_path}. Please try again."))
        elif choice.startswith("2"):
            # Edit hash mode
            config['hash_mode'] = self._manual_hash_mode(default=config['hash_mode'])
        elif choice.startswith("3"):
            # Edit attack mode
            attack_choice = questionary.select("Choose attack mode", choices=list(ATTACK_MODES.keys()),
                                             default=config['attack_choice']).ask()
            config['attack_mode'] = ATTACK_MODES[attack_choice]
            config['attack_choice'] = attack_choice
        elif choice.startswith("4"):
            # Edit wordlists
            wordlist_keys = self._pick_assets("wordlists")
            if wordlist_keys:
                self.asset_manager.sync(wordlist_keys)
                failed = getattr(self.asset_manager, 'errors', {})
                for key, err in failed.items():
                    self.console.print(f"[yellow]⚠  {key}:[/yellow] {err}")
                config['wordlist_keys'] = [k for k in wordlist_keys if k not in failed]
        elif choice.startswith("5"):
            # Edit rules
            rule_keys = self._pick_assets("rules")
            if rule_keys:
                self.asset_manager.sync(rule_keys)
                failed = getattr(self.asset_manager, 'errors', {})
                for key, err in failed.items():
                    self.console.print(f"[yellow]⚠  {key}:[/yellow] {err}")
                config['rule_keys'] = [k for k in rule_keys if k not in failed]
            else:
                config['rule_keys'] = []
        elif choice.startswith("6"):
            # Edit webhook
            config['webhook'] = self._prompt_discord()

        return True

    def _execute_configuration(self, config: dict) -> None:
        """Execute hashcat — either deploy to Vast.ai or run locally."""
        from .notifier import Notifier
        wordlist_paths = self.asset_manager.resolved_paths(config.get('wordlist_keys', []))
        rule_paths     = self.asset_manager.resolved_paths(config.get('rule_keys', []))
        notifier = Notifier(
            discord_webhook=config.get('webhook'),
            slack_webhook=config.get('slack_webhook'),
            pushover_token=config.get('pushover_token'),
            pushover_user=config.get('pushover_user'),
        )

        wordlist_files = self._only_files(wordlist_paths, "wordlist")
        rule_files     = self._only_files(rule_paths, "rule")
        remote_output  = config.get('output_file') or "/root/cracked.txt"

        command_local = render_hashcat_command(
            hash_path=config['hash_path'],
            hash_mode=config['hash_mode'],
            attack_mode=config['attack_mode'],
            wordlists=wordlist_files,
            rules=rule_files,
            output_file=config.get('output_file'),
            workload=config.get('workload'),
            mask=config.get('mask'),
        )

        self.console.rule(cat_say("Hashcat Command"))
        self.console.print(f"\n[bold]Command (local reference):[/bold]\n[italic]{command_local}[/italic]\n")

        # ── Vast.ai deployment ───────────────────────────────────────────────
        if config.get('vast_deploy') and config.get('vast_offer'):
            # _deploy_to_vast builds the remote command itself from config keys
            self._deploy_to_vast(config, wordlist_files, rule_files, "", remote_output, notifier)
            return

        # ── Local execution ──────────────────────────────────────────────────
        if config.get('show_potfile'):
            show_cmd = f"hashcat -m {config['hash_mode']} {config['hash_path']} --show"
            self.console.print(f"[bold]Check potfile:[/bold] [dim]{show_cmd}[/dim]")
            if questionary.confirm("Run --show now?", default=True).ask():
                runner = HashcatRunner(notifier=Notifier())
                try:
                    runner.ensure_binary()
                    runner.run(shlex.split(show_cmd)[1:])
                except Exception:
                    pass

        script = render_startup_script(wordlist_paths + rule_paths)
        if questionary.confirm("Save script to file?", default=True).ask():
            path = Path(questionary.text("Path", default="vastcat-run.sh").ask())
            path.write_text(script + f"\n{command_local}\n")
            os.chmod(path, 0o750)
            self.console.print(cat_say(f"Script saved to {path}"))

        if questionary.confirm("Run hashcat locally now?", default=False).ask():
            runner = HashcatRunner(binary=os.environ.get("HASHCAT_BINARY"), notifier=notifier)
            try:
                runner.ensure_binary()
                runner.run(shlex.split(command_local)[1:])
            except FileNotFoundError as exc:
                self.console.print(f"[red]{exc}[/red]")
            except PermissionError as exc:
                self.console.print(f"[red]Permission error:[/red] {exc}")

    def _deploy_to_vast(
        self,
        config: dict,
        wordlist_files: List[str],
        rule_files: List[str],
        _unused_remote_command: str,
        remote_output: str,
        notifier,
    ) -> None:
        """Create a Vast.ai instance with a self-contained onstart script.

        The hash file is embedded directly in the onstart script — no SCP,
        no race condition, works from any machine regardless of SSH key setup.
        Wordlists and rules are downloaded directly on the instance from source URLs.
        """
        from .vast import VastClient, VastError

        offer  = config['vast_offer']
        client = VastClient(config['vast_api_key'])

        # Read hash file content to embed in onstart (avoids SCP race condition)
        try:
            hash_content = Path(config['hash_path']).read_text(errors='ignore').strip()
        except OSError as exc:
            self.console.print(f"[red]Cannot read hash file:[/red] {exc}")
            return

        # Build remote asset descriptors from original source URLs
        wordlist_assets = remote_assets_from_keys(
            config.get('wordlist_keys', []), "/root/wordlists"
        )
        rule_assets = remote_assets_from_keys(
            config.get('rule_keys', []), "/root/rules"
        )

        remote_wordlists = [f"/root/wordlists/{a.output_name}" for a in wordlist_assets]
        remote_rules     = [f"/root/rules/{a.output_name}"     for a in rule_assets]

        hashcat_command = render_hashcat_command(
            hash_path="/root/hashes.txt",
            hash_mode=config['hash_mode'],
            attack_mode=config['attack_mode'],
            wordlists=remote_wordlists,
            rules=remote_rules,
            output_file=remote_output,
            workload=config.get('workload'),
            mask=config.get('mask'),
        )

        # Optional Pushover notification baked into the onstart script
        notif_cmd = None
        if config.get('pushover_token') and config.get('pushover_user'):
            notif_cmd = (
                f'curl -s -F "token={config["pushover_token"]}" '
                f'-F "user={config["pushover_user"]}" '
                f'-F "title=Vastcat done" '
                f'-F "message=Job complete — results at {remote_output}" '
                f'https://api.pushover.net/1/messages.json'
            )

        onstart = render_onstart_script(
            hash_content=hash_content,
            wordlist_assets=wordlist_assets,
            rule_assets=rule_assets,
            hashcat_command=hashcat_command,
            output_file=remote_output,
            notification_cmd=notif_cmd,
        )

        self.console.print(cat_say(f"Creating instance — {offer.gpu_name} @ ${offer.hourly:.3f}/hr..."))
        try:
            instance = client.create_instance(
                offer_id=offer.id,
                image=config['vast_image'],
                disk_gb=config.get('vast_disk_gb', 20),
                label="vastcat",
                onstart=onstart,
            )
        except VastError as exc:
            self.console.print(f"[red]Failed to create instance:[/red] {exc}")
            return

        self.console.print(f"[green]✓[/green] Instance {instance.id} created — waiting for boot...")
        notifier.notify("Vastcat", f"Instance {instance.id} starting on {offer.gpu_name}")

        try:
            instance = client.wait_for_running(instance.id, timeout_s=600, poll_s=10)
        except VastError as exc:
            self.console.print(f"[red]Instance failed to start:[/red] {exc}")
            return

        self.console.print(f"[green]✓[/green] Running — {client.ssh_command(instance)}")
        self.console.print(cat_say(
            f"Downloading {len(wordlist_assets)} wordlist(s) + "
            f"{len(rule_assets)} rule(s) on instance — hashcat starts automatically."
        ))

        notifier.notify(
            "Vastcat started",
            f"Instance {instance.id} ({offer.gpu_name}) downloading assets and cracking"
        )

        self.console.rule("Instance Info")
        self.console.print(f"[bold]Instance ID:[/bold]   {instance.id}")
        self.console.print(f"[bold]SSH:[/bold]           {client.ssh_command(instance)}")
        self.console.print(f"[bold]Monitor log:[/bold]   ssh ... 'tail -f /root/vastcat.log'")
        self.console.print(f"[bold]Results:[/bold]       ssh ... 'cat {remote_output}'")
        self.console.print(f"[bold]Destroy:[/bold]       vastcat vast destroy {instance.id}")
        self.console.print(f"\n[yellow]Cost: ~${offer.hourly:.3f}/hr — destroy when done![/yellow]\n")

    def _pick_assets(self, category: str) -> List[str]:
        """Pick assets using a numbered menu (more reliable than arrow keys)."""
        keys = list_assets(category)
        if not keys:
            return []

        # Display available options
        self.console.print(f"\n[bold]Available {category}:[/bold]")

        # For rules, add a "no rules" option at index 0
        if category == "rules":
            self.console.print(f"  [cyan]0[/cyan]. No rules (straight wordlist attack)")

        for idx, key in enumerate(keys, 1):
            asset = ASSET_LIBRARY[key]
            self.console.print(f"  [cyan]{idx}[/cyan]. {key}: [dim]{asset.description}[/dim]")

        # Get selection
        self.console.print(f"\n[bold]Enter numbers to select {category}:[/bold]")
        if category == "rules":
            self.console.print("[dim]Examples: '0' (no rules), '1' (single), '1,2' (multiple), '1-3' (range), 'all' (select all)[/dim]")
        else:
            self.console.print("[dim]Examples: '1' (single), '1,2' (multiple), '1-3' (range), 'all' (select all)[/dim]")

        selection = questionary.text(
            f"Select {category}",
            default="all" if category == "wordlists" else ""
        ).ask()

        if not selection or selection.strip() == "":
            return []

        # Handle "0" for no rules
        if category == "rules" and selection.strip() == "0":
            self.console.print(f"[green]✓[/green] No rules selected (straight wordlist attack)")
            return []

        # Parse selection
        try:
            selected_indices = self._parse_selection(selection.strip(), len(keys))
            selected_keys = [keys[i] for i in selected_indices]

            if selected_keys:
                self.console.print(f"[green]✓[/green] Selected {len(selected_keys)} {category}: {', '.join(selected_keys)}")
            return selected_keys
        except ValueError as e:
            self.console.print(f"[red]Invalid selection:[/red] {e}")
            return []

    def _parse_selection(self, selection: str, max_items: int) -> List[int]:
        """Parse user selection string into list of indices.

        Supports:
        - Single: "1"
        - Multiple: "1,2,3"
        - Range: "1-3"
        - All: "all"
        - Mixed: "1,3-5,7"

        Returns 0-based indices.
        """
        if selection.lower() == "all":
            return list(range(max_items))

        indices = set()
        parts = selection.split(",")

        for part in parts:
            part = part.strip()
            if "-" in part:
                # Range: "1-3"
                try:
                    start, end = part.split("-")
                    start_idx = int(start.strip()) - 1
                    end_idx = int(end.strip()) - 1

                    if start_idx < 0 or end_idx >= max_items or start_idx > end_idx:
                        raise ValueError(f"Range {part} is invalid (valid: 1-{max_items})")

                    indices.update(range(start_idx, end_idx + 1))
                except ValueError as e:
                    if "invalid literal" in str(e):
                        raise ValueError(f"Invalid range format: {part}")
                    raise
            else:
                # Single number
                try:
                    idx = int(part) - 1
                    if idx < 0 or idx >= max_items:
                        raise ValueError(f"Number {part} is out of range (valid: 1-{max_items})")
                    indices.add(idx)
                except ValueError as e:
                    if "invalid literal" in str(e):
                        raise ValueError(f"Invalid number: {part}")
                    raise

        return sorted(list(indices))

    def _prompt_discord(self) -> Optional[str]:
        default = self.config.get("discord_webhook")
        webhook = questionary.text("Discord webhook (optional)", default=default or "").ask()
        if webhook:
            self.config.set("discord_webhook", webhook)
        return webhook

    def _only_files(self, paths: List[Path], label: str) -> List[str]:
        files: List[str] = []
        for path in paths:
            if path.is_file():
                files.append(str(path))
            else:
                self.console.print(cat_say(f"Skipping {label} target {path} (not a file)."))
        return files

    def _determine_hash_mode(self, hash_path: str) -> str:
        sample = sample_from_file(hash_path)
        if not sample:
            self.console.print(cat_say("Could not read a hash sample; please enter the mode manually."))
            return self._manual_hash_mode()
        guesses = detect_hash_modes(sample)
        if not guesses:
            self.console.print(cat_say("No matching hash types detected. Falling back to manual entry."))
            return self._manual_hash_mode()
        self.console.print(cat_say(f"Sample hash snippet: {sample[:24]}..."))
        choices = [
            Choice(
                title=f"{guess.name} (mode {guess.mode}) — {guess.reason}",
                value=guess.mode,
            )
            for guess in guesses
        ]
        choices.append(Choice(title="Enter manually", value="__manual__"))
        selection = questionary.select(
            "Detected hash types (confirm or pick manually)",
            choices=choices,
        ).ask()
        if selection == "__manual__":
            return self._manual_hash_mode()
        chosen = self._guess_from_mode(guesses, selection)
        if chosen:
            self.console.print(cat_say(f"Using {chosen.name} (mode {chosen.mode})."))
        return selection

    def _manual_hash_mode(self, default: str = "0") -> str:
        return questionary.text("Hashcat hash mode", default=default).ask()

    def _guess_from_mode(self, guesses: List[HashGuess], mode: str) -> Optional[HashGuess]:
        for guess in guesses:
            if guess.mode == mode:
                return guess
        return None
