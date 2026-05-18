"""Vast.ai API client."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

BASE_URL = "https://console.vast.ai/api/v0"


class VastError(RuntimeError):
    pass


@dataclass
class Offer:
    id: int
    gpu_name: str
    num_gpus: int
    hourly: float
    vram_gb: float
    reliability: float
    disk_space: float
    inet_up: float
    inet_down: float
    cuda_version: str
    ssh_host: str
    ssh_port: int

    @classmethod
    def from_api(cls, d: Dict[str, Any]) -> "Offer":
        return cls(
            id=int(d["id"]),
            gpu_name=d.get("gpu_name", ""),
            num_gpus=int(d.get("num_gpus", 1)),
            hourly=float(d.get("dph_total", 0.0)),
            vram_gb=float(d.get("gpu_ram", 0.0)) / 1024,  # MB → GB
            reliability=float(d.get("reliability2", 0.0)),
            disk_space=float(d.get("disk_space", 0.0)),
            inet_up=float(d.get("inet_up", 0.0)),
            inet_down=float(d.get("inet_down", 0.0)),
            cuda_version=str(d.get("cuda_max_good", "")),
            ssh_host=d.get("ssh_host", ""),
            ssh_port=int(d.get("ssh_port", 22)),
        )

    def display(self) -> str:
        return (
            f"${self.hourly:.3f}/hr  {self.num_gpus}x {self.gpu_name} "
            f"({self.vram_gb:.0f}GB VRAM)  reliability={self.reliability:.2f}  "
            f"↑{self.inet_up:.0f}/↓{self.inet_down:.0f} Mbps  id={self.id}"
        )


@dataclass
class Instance:
    id: int
    status: str       # created, running, exited, etc.
    gpu_name: str
    num_gpus: int
    hourly: float
    ssh_host: str
    ssh_port: int
    label: str

    @classmethod
    def from_api(cls, d: Dict[str, Any]) -> "Instance":
        return cls(
            id=int(d["id"]),
            status=d.get("actual_status") or d.get("status", "unknown"),
            gpu_name=d.get("gpu_name", ""),
            num_gpus=int(d.get("num_gpus", 1)),
            hourly=float(d.get("dph_total", 0.0)),
            ssh_host=d.get("ssh_host", ""),
            ssh_port=int(d.get("ssh_port", 22)),
            label=d.get("label", ""),
        )


class VastClient:
    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key or os.environ.get("VAST_API_KEY") or ""
        if not self.api_key:
            raise VastError("Missing Vast.ai API key. Set VAST_API_KEY env var or pass it in.")

    def _get(self, path: str, params: Optional[Dict] = None) -> Any:
        params = params or {}
        params["api_key"] = self.api_key
        resp = requests.get(f"{BASE_URL}{path}", params=params, timeout=20)
        if not resp.ok:
            raise VastError(f"GET {path} failed ({resp.status_code}): {resp.text}")
        return resp.json()

    def _post(self, path: str, payload: Optional[Dict] = None) -> Any:
        resp = requests.put(
            f"{BASE_URL}{path}",
            params={"api_key": self.api_key},
            json=payload or {},
            timeout=30,
        )
        if not resp.ok:
            raise VastError(f"POST {path} failed ({resp.status_code}): {resp.text}")
        return resp.json()

    def _delete(self, path: str) -> Any:
        resp = requests.delete(
            f"{BASE_URL}{path}",
            params={"api_key": self.api_key},
            timeout=20,
        )
        if not resp.ok:
            raise VastError(f"DELETE {path} failed ({resp.status_code}): {resp.text}")
        return resp.json()

    def search_offers(
        self,
        min_vram_gb: float = 8,
        max_hourly: float = 1.0,
        min_reliability: float = 0.9,
        gpu_name: Optional[str] = None,
        top_n: int = 10,
    ) -> List[Offer]:
        """Search for GPU offers matching the given constraints."""
        import json
        q: Dict[str, Any] = {
            "verified": {"eq": True},
            "reliability2": {"gte": min_reliability},
            "dph_total": {"lte": max_hourly},
            "gpu_ram": {"gte": min_vram_gb * 1024},  # GB → MB
            "rentable": {"eq": True},
            "rented": {"eq": False},
        }
        if gpu_name:
            q["gpu_name"] = {"eq": gpu_name}

        data = self._get("/bundles/", {"q": json.dumps(q)})
        offers = data.get("offers", [])
        offers.sort(key=lambda o: float(o.get("dph_total", 999)))
        return [Offer.from_api(o) for o in offers[:top_n]]

    def create_instance(
        self,
        offer_id: int,
        image: str,
        disk_gb: int = 20,
        label: str = "vastcat",
        onstart: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> Instance:
        """Rent an instance from an offer."""
        payload: Dict[str, Any] = {
            "client_id": "me",
            "image": image,
            "disk": disk_gb,
            "label": label,
            "runtype": "ssh",
        }
        if onstart:
            payload["onstart"] = onstart
        if env:
            payload["env"] = env

        data = self._post(f"/asks/{offer_id}/", payload)
        new_contract = data.get("new_contract")
        if not new_contract:
            raise VastError(f"Instance creation failed: {data}")
        return self.get_instance(new_contract)

    def list_instances(self) -> List[Instance]:
        """List all your current instances."""
        data = self._get("/instances/", {"owner": "me"})
        return [Instance.from_api(i) for i in data.get("instances", [])]

    def get_instance(self, instance_id: int) -> Instance:
        data = self._get("/instances/", {"owner": "me"})
        for i in data.get("instances", []):
            if int(i["id"]) == instance_id:
                return Instance.from_api(i)
        raise VastError(f"Instance {instance_id} not found")

    def destroy_instance(self, instance_id: int) -> None:
        self._delete(f"/instances/{instance_id}/")

    def wait_for_running(self, instance_id: int, timeout_s: int = 300, poll_s: int = 10) -> Instance:
        """Poll until instance status is 'running' or timeout."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            inst = self.get_instance(instance_id)
            if inst.status == "running":
                return inst
            if inst.status in ("exited", "deleted", "error"):
                raise VastError(f"Instance {instance_id} entered status '{inst.status}'")
            time.sleep(poll_s)
        raise VastError(f"Instance {instance_id} did not reach 'running' within {timeout_s}s")

    def ssh_command(self, instance: Instance) -> str:
        """Return an SSH command string for connecting to the instance."""
        return f"ssh -p {instance.ssh_port} root@{instance.ssh_host}"

    def upload_file(self, instance: Instance, local_path: str, remote_path: str) -> None:
        """SCP a file to the instance. Requires ssh/scp on the local machine."""
        import subprocess
        cmd = [
            "scp", "-P", str(instance.ssh_port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            local_path,
            f"root@{instance.ssh_host}:{remote_path}",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise VastError(f"SCP failed: {result.stderr}")

    def run_remote(self, instance: Instance, command: str) -> str:
        """Run a command on the instance via SSH and return stdout."""
        import subprocess
        cmd = [
            "ssh", "-p", str(instance.ssh_port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            f"root@{instance.ssh_host}",
            command,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise VastError(f"Remote command failed: {result.stderr}")
        return result.stdout
