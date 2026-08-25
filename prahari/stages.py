"""Classify boot events into distinct Linux boot phases and detect phase violations."""
from dataclasses import dataclass
from enum import Enum


class BootStage(str, Enum):
    FIRMWARE_UEFI = "Firmware/UEFI"
    KERNEL_CORE = "Kernel Core"
    EARLY_USERSPACE = "Early Userspace"
    INIT_SYSTEM = "Init/Systemd"
    KERNEL_MODULES = "Kernel Modules"
    SYSTEM_SERVICES = "System Services"
    UNKNOWN = "Unknown/Other"


STAGE_ORDER = [
    BootStage.FIRMWARE_UEFI,
    BootStage.KERNEL_CORE,
    BootStage.EARLY_USERSPACE,
    BootStage.INIT_SYSTEM,
    BootStage.KERNEL_MODULES,
    BootStage.SYSTEM_SERVICES,
]

STAGE_INDEX = {s: i for i, s in enumerate(STAGE_ORDER)}


def classify_path(path: str) -> BootStage:
    """Determine the boot phase for a measured component."""
    p = path.replace("\\", "/").lower()
    
    if p in ("boot_aggregate", "tpm", "firmware") or "ovmf" in p or "grub" in p or "shim" in p:
        return BootStage.FIRMWARE_UEFI
    if "moklist" in p or "secureboot" in p or "pcr" in p:
        return BootStage.FIRMWARE_UEFI
        
    if "vmlinuz" in p or "initrd" in p or "initramfs" in p or "cmdline" in p:
        return BootStage.KERNEL_CORE
    if p.startswith("/boot/"):
        return BootStage.KERNEL_CORE
        
    if p in ("/init", "/bin/busybox", "/etc/fstab", "/etc/ld.so.cache"):
        return BootStage.EARLY_USERSPACE
    if p.startswith("/lib/x86_64-linux-gnu/libc.so") or p.startswith("/lib64/ld-linux"):
        return BootStage.EARLY_USERSPACE
        
    if "systemd" in p or p in ("/sbin/init", "/bin/systemd", "/etc/inittab"):
        return BootStage.INIT_SYSTEM
        
    if p.endswith(".ko") or p.endswith(".ko.xz") or p.endswith(".ko.zst") or "/modules/" in p:
        return BootStage.KERNEL_MODULES
        
    if p.startswith("/usr/bin") or p.startswith("/usr/sbin") or p.startswith("/etc/"):
        return BootStage.SYSTEM_SERVICES
    if p.startswith("/bin/") or p.startswith("/sbin/"):
        return BootStage.SYSTEM_SERVICES
        
    return BootStage.UNKNOWN


@dataclass
class PhaseAnomaly:
    event_index: int
    path: str
    stage: BootStage
    detail: str


def check_stage_transitions(events):
    """Scan event stream for high-level boot stage anomalies."""
    anomalies = []
    max_stage_idx = 0
    
    for i, event in enumerate(events):
        stage = classify_path(event.path)
        if stage == BootStage.UNKNOWN:
            continue
        idx = STAGE_INDEX.get(stage, -1)
        if idx < 0:
            continue
            
        if idx < max_stage_idx - 1 and max_stage_idx >= 3:
            anomalies.append(PhaseAnomaly(
                event_index=i,
                path=event.path,
                stage=stage,
                detail=f"Component from early stage '{stage.value}' executed during late stage '{STAGE_ORDER[max_stage_idx].value}'"
            ))
        else:
            if idx > max_stage_idx:
                max_stage_idx = idx
                
    return anomalies
