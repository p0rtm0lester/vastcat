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


# Minimum CUDA compute capability for hashcat GPU support.
# 6.0 = Pascal (GTX 1080/1070 era) — anything older is not worth using.
HASHCAT_MIN_COMPUTE_CAP = 60   # stored as integer, e.g. 86 = compute 8.6
HASHCAT_MIN_CUDA        = 11.0 # CUDA 11.0+ required for hashcat 6.x

# Approximate hashcat MD5 throughput (GH/s) per card.
# Used to rank offers by cracking efficiency (GH/s per dollar).
# Sources: hashcat benchmark wiki + community benchmarks.
GPU_SPEED_GHS: Dict[str, float] = {
    # Blackwell
    "RTX 5090":    300.0,
    "RTX 5080":    200.0,
    "RTX 5070 Ti": 155.0,
    "RTX 5070":    130.0,
    "RTX 5060 Ti":  80.0,
    # Ada Lovelace
    "RTX 4090":    164.0,
    "RTX 4080 Super": 115.0,
    "RTX 4080":    105.0,
    "RTX 4070 Ti Super": 90.0,
    "RTX 4070 Ti":  82.0,
    "RTX 4070 Super": 74.0,
    "RTX 4070S":    74.0,
    "RTX 4070":     67.0,
    "RTX 4060 Ti":  48.0,
    "RTX 4060":     38.0,
    # Ampere consumer
    "RTX 3090 Ti": 110.0,
    "RTX 3090":     98.0,
    "RTX 3080 Ti":  87.0,
    "RTX 3080":     82.0,
    "RTX 3070 Ti":  72.0,
    "RTX 3070":     67.0,
    "RTX 3060 Ti":  55.0,
    "RTX 3060":     44.0,
    "RTX 3050":     30.0,
    # Ampere datacenter
    "A100":        180.0,
    "A40":         108.0,
    "A6000":       110.0,
    "A5000":        95.0,
    "A4000":        78.0,
    "A30":          72.0,
    "A10":          60.0,
    "A16":          46.0,
    # Hopper / Lovelace datacenter
    "H100":        260.0,
    "L40S":        135.0,
    "L40":         120.0,
    "L4":           45.0,
    # Turing
    "RTX 2080 Ti":  62.0,
    "RTX 2080 Super": 55.0,
    "RTX 2080":     49.0,
    "RTX 2070 Super": 48.0,
    "RTX 2070":     44.0,
    "RTX 2060 Super": 40.0,
    "RTX 2060":     36.0,
    "T4":           28.0,
    # Volta
    "V100":         92.0,
    "Titan V":      82.0,
    # Pascal
    "GTX 1080 Ti":  41.0,
    "GTX 1080":     33.0,
    "GTX 1070 Ti":  28.0,
    "GTX 1070":     26.0,
    "GTX 1060":     16.0,
    "P100":         46.0,
    # Titan
    "Titan RTX":    68.0,
    "Titan Xp":     36.0,
}


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
    cuda_version: float
    compute_cap: int   # e.g. 86 = compute 8.6 (Ampere)
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
            cuda_version=float(d.get("cuda_max_good") or 0),
            compute_cap=int(d.get("compute_cap") or 0),
            ssh_host=d.get("ssh_host", ""),
            ssh_port=int(d.get("ssh_port", 22)),
        )

    def speed_ghs(self) -> float:
        """Estimated MD5 hashcat speed in GH/s for this offer."""
        base = 0.0
        name = self.gpu_name
        # Try longest match first (e.g. "RTX 4070 Ti Super" before "RTX 4070")
        for key in sorted(GPU_SPEED_GHS, key=len, reverse=True):
            if key.lower() in name.lower():
                base = GPU_SPEED_GHS[key]
                break
        return base * self.num_gpus

    def efficiency(self) -> float:
        """GH/s per dollar — higher is better."""
        if self.hourly <= 0:
            return 0.0
        return self.speed_ghs() / self.hourly

    def display(self, rank: int = 0, best_efficiency: float = 0.0) -> str:
        """Single-line display for use in a selection menu."""
        speed = self.speed_ghs()
        eff   = self.efficiency()
        gpus  = f"{self.num_gpus}x " if self.num_gpus > 1 else ""
        vram  = f"{self.vram_gb:.0f}GB"
        price = f"${self.hourly:.3f}/hr"
        spd   = f"~{speed:.0f} GH/s" if speed else "speed unknown"
        rel   = f"{self.reliability * 100:.0f}% uptime"

        # Value badge
        if best_efficiency > 0 and eff >= best_efficiency * 0.95:
            badge = "★ BEST  "
        elif best_efficiency > 0 and eff >= best_efficiency * 0.80:
            badge = "▲ GOOD  "
        else:
            badge = "        "

        return f"{badge}{gpus}{self.gpu_name:<18} {vram:<5} CUDA {self.cuda_version:<4}  {price:<10} {spd:<16} {rel}"


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
        cuda_only: bool = True,
    ) -> List[Offer]:
        """Search for GPU offers compatible with hashcat CUDA.

        By default (cuda_only=True) filters to NVIDIA CUDA instances with:
          - CUDA driver >= 11.0
          - Compute capability >= 6.0 (Pascal / GTX 10xx and newer)
        """
        import json
        q: Dict[str, Any] = {
            "verified":   {"eq": True},
            "reliability2": {"gte": min_reliability},
            "dph_total":  {"lte": max_hourly},
            "gpu_ram":    {"gte": min_vram_gb * 1024},  # GB → MB
            "rentable":   {"eq": True},
            "rented":     {"eq": False},
        }

        if cuda_only:
            q["cuda_max_good"] = {"gte": HASHCAT_MIN_CUDA}
            q["compute_cap"]   = {"gte": HASHCAT_MIN_COMPUTE_CAP}

        if gpu_name:
            q["gpu_name"] = {"eq": gpu_name}

        data = self._get("/bundles/", {"q": json.dumps(q)})
        raw = data.get("offers", [])
        offers = [Offer.from_api(o) for o in raw]

        # Sort by efficiency (GH/s per dollar) descending.
        # Unknown GPUs fall back to price-ascending so they appear at the end.
        known   = sorted([o for o in offers if o.speed_ghs() > 0],
                         key=lambda o: o.efficiency(), reverse=True)
        unknown = sorted([o for o in offers if o.speed_ghs() == 0],
                         key=lambda o: o.hourly)
        return (known + unknown)[:top_n]

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
