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

# Approximate hashcat NTLM (mode 1000) throughput in GH/s per card.
# NTLM is the reference because it's the most common red team target
# (AD hash dumps, responder captures) and scales well across GPU generations.
# Sources: hashcat benchmark wiki, community benchmarks, vast.ai dlperf data.
GPU_SPEED_NTLM_GHS: Dict[str, float] = {
    # Blackwell
    "RTX 5090":        480.0,
    "RTX 5080":        320.0,
    "RTX 5070 Ti":     250.0,
    "RTX 5070":        210.0,
    "RTX 5060 Ti":     130.0,
    # Ada Lovelace
    "RTX 4090":        264.0,
    "RTX 4080 Super":  180.0,
    "RTX 4080":        165.0,
    "RTX 4070 Ti Super": 145.0,
    "RTX 4070 Ti":     132.0,
    "RTX 4070 Super":  120.0,
    "RTX 4070S":       120.0,
    "RTX 4070":        107.0,
    "RTX 4060 Ti":      78.0,
    "RTX 4060":         60.0,
    # Ampere consumer
    "RTX 3090 Ti":     175.0,
    "RTX 3090":        155.0,
    "RTX 3080 Ti":     140.0,
    "RTX 3080":        125.0,
    "RTX 3070 Ti":     115.0,
    "RTX 3070":        105.0,
    "RTX 3060 Ti":      88.0,
    "RTX 3060":         68.0,
    "RTX 3050":         48.0,
    # Ampere datacenter
    "A100":            280.0,
    "A40":             165.0,
    "A6000":           170.0,
    "A5000":           148.0,
    "A4000":           118.0,
    "A30":             110.0,
    "A10":              95.0,
    "A16":              72.0,
    # Hopper / Lovelace datacenter
    "H100":            410.0,
    "L40S":            215.0,
    "L40":             190.0,
    "L4":               72.0,
    # Turing
    "RTX 2080 Ti":      95.0,
    "RTX 2080 Super":   88.0,
    "RTX 2080":         78.0,
    "RTX 2070 Super":   76.0,
    "RTX 2070":         70.0,
    "RTX 2060 Super":   64.0,
    "RTX 2060":         57.0,
    "T4":               44.0,
    # Volta
    "V100":            145.0,
    "Titan V":         130.0,
    # Pascal
    "GTX 1080 Ti":      65.0,
    "GTX 1080":         52.0,
    "GTX 1070 Ti":      45.0,
    "GTX 1070":         41.0,
    "GTX 1060":         25.0,
    "P100":             72.0,
    # Titan
    "Titan RTX":       108.0,
    "Titan Xp":         57.0,
}

# Speed multipliers relative to NTLM for common hash modes.
# Used to estimate real-world speed for the hash type being cracked.
HASH_MODE_MULTIPLIER: Dict[str, float] = {
    "0":     0.65,   # MD5         — slower than NTLM
    "100":   0.40,   # SHA-1
    "1000":  1.00,   # NTLM        — reference
    "1400":  0.20,   # SHA-256
    "1700":  0.06,   # SHA-512
    "1800":  0.0002, # sha512crypt — very slow
    "300":   0.005,  # MySQL4.1    — double SHA-1, very slow
    "500":   0.0005, # md5crypt
    "3200":  0.0001, # bcrypt      — extremely slow
    "5500":  0.45,   # NetNTLMv1
    "5600":  0.25,   # NetNTLMv2
    "13100": 0.05,   # Kerberos TGS RC4
    "19600": 0.03,   # Kerberos TGS AES-128
    "19700": 0.02,   # Kerberos TGS AES-256
    "18200": 0.05,   # Kerberos AS-REP
    "22000": 0.004,  # WPA2-PMKID
    "2500":  0.004,  # WPA2
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

    def ntlm_ghs(self) -> float:
        """Estimated NTLM hashcat speed in GH/s — used for ranking."""
        base = 0.0
        name = self.gpu_name
        for key in sorted(GPU_SPEED_NTLM_GHS, key=len, reverse=True):
            if key.lower() in name.lower():
                base = GPU_SPEED_NTLM_GHS[key]
                break
        return base * self.num_gpus

    def speed_for_mode(self, hash_mode: str = "1000") -> float:
        """Estimated hashcat speed in GH/s for a specific hash mode."""
        multiplier = HASH_MODE_MULTIPLIER.get(str(hash_mode), 1.0)
        return self.ntlm_ghs() * multiplier

    def efficiency(self, hash_mode: str = "1000") -> float:
        """GH/s per dollar for a given hash mode — higher is better."""
        if self.hourly <= 0:
            return 0.0
        return self.speed_for_mode(hash_mode) / self.hourly

    def display(self, best_efficiency: float = 0.0, hash_mode: str = "1000") -> str:
        """Single-line display for use in a selection menu."""
        speed = self.speed_for_mode(hash_mode)
        eff   = self.efficiency(hash_mode)
        gpus  = f"{self.num_gpus}x " if self.num_gpus > 1 else ""
        vram  = f"{self.vram_gb:.0f}GB"
        price = f"${self.hourly:.3f}/hr"

        # Format speed readably: GH/s, MH/s, or KH/s depending on magnitude
        if speed >= 1.0:
            spd = f"~{speed:.0f} GH/s"
        elif speed >= 0.001:
            spd = f"~{speed*1000:.0f} MH/s"
        else:
            spd = f"~{speed*1e6:.0f} KH/s"

        rel = f"{self.reliability * 100:.0f}% uptime"

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
        hash_mode: str = "1000",
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

        # Sort by efficiency for the specific hash mode being cracked.
        known   = sorted([o for o in offers if o.ntlm_ghs() > 0],
                         key=lambda o: o.efficiency(hash_mode), reverse=True)
        unknown = sorted([o for o in offers if o.ntlm_ghs() == 0],
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
