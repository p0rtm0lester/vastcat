"""Notification helpers — Discord, Slack, and Pushover."""
from __future__ import annotations

from typing import Optional
import json
import requests


class Notifier:
    def __init__(
        self,
        discord_webhook: Optional[str] = None,
        slack_webhook: Optional[str] = None,
        pushover_token: Optional[str] = None,
        pushover_user: Optional[str] = None,
    ) -> None:
        self.discord_webhook = discord_webhook
        self.slack_webhook = slack_webhook
        self.pushover_token = pushover_token
        self.pushover_user = pushover_user

    @classmethod
    def from_config(cls, config) -> "Notifier":
        return cls(
            discord_webhook=config.get("discord_webhook"),
            slack_webhook=config.get("slack_webhook"),
            pushover_token=config.get("pushover_token"),
            pushover_user=config.get("pushover_user"),
        )

    def notify(self, title: str, message: str) -> None:
        self._discord(title, message)
        self._slack(title, message)
        self._pushover(title, message)

    def _discord(self, title: str, message: str) -> None:
        if not self.discord_webhook:
            return
        payload = {
            "username": "Vastcat",
            "embeds": [{"title": title, "description": message, "color": 0xF4A460}],
        }
        try:
            requests.post(
                self.discord_webhook,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=10,
            ).raise_for_status()
        except Exception:
            pass

    def _slack(self, title: str, message: str) -> None:
        if not self.slack_webhook:
            return
        try:
            requests.post(
                self.slack_webhook,
                json={"text": f"*{title}*\n{message}"},
                timeout=10,
            ).raise_for_status()
        except Exception:
            pass

    def _pushover(self, title: str, message: str) -> None:
        if not (self.pushover_token and self.pushover_user):
            return
        try:
            requests.post(
                "https://api.pushover.net/1/messages.json",
                data={
                    "token": self.pushover_token,
                    "user": self.pushover_user,
                    "title": title,
                    "message": message,
                },
                timeout=10,
            ).raise_for_status()
        except Exception:
            pass
