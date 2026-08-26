import getpass
import os
import platform
import plistlib
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .models import Finding


def run_command(args: List[str], timeout: int = 10) -> Tuple[int, str]:
    """Run a read-only system command and return (exit_code, combined_output)."""
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = "\n".join(part.strip() for part in (proc.stdout, proc.stderr) if part.strip())
        return proc.returncode, output.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)


def system_info() -> Dict[str, str]:
    info = {
        "hostname": platform.node() or "Unknown",
        "current_user": getpass.getuser(),
        "architecture": platform.machine() or "Unknown",
        "macos_version": "Unknown",
        "macos_build": "Unknown",
        "model": "Unknown",
        "chip": "Unknown",
    }

    rc, out = run_command(["/usr/bin/sw_vers", "-productVersion"])
    if rc == 0 and out:
        info["macos_version"] = out

    rc, out = run_command(["/usr/bin/sw_vers", "-buildVersion"])
    if rc == 0 and out:
        info["macos_build"] = out

    rc, out = run_command(["/usr/sbin/system_profiler", "SPHardwareDataType", "-xml"], timeout=20)
    if rc == 0 and out:
        try:
            data = plistlib.loads(out.encode())
            items = data[0].get("_items", []) if data else []
            if items:
                item = items[0]
                info["model"] = item.get("machine_name") or item.get("model_name") or "Unknown"
                info["chip"] = item.get("chip_type") or item.get("cpu_type") or "Unknown"
        except Exception:
            pass

    return info


def check_filevault() -> Finding:
    rc, out = run_command(["/usr/bin/fdesetup", "status"])
    normalized = out.lower()
    if rc == 0 and "filevault is on" in normalized:
        return Finding(
            "FV-001", "FileVault disk encryption", "Data Protection", "PASS", "high",
            20, 20, out, "Keep FileVault enabled and escrow recovery keys through approved management tooling.", out
        )
    if "filevault is off" in normalized:
        return Finding(
            "FV-001", "FileVault disk encryption", "Data Protection", "FAIL", "high",
            20, 0, out, "Enable FileVault and ensure an organization-approved recovery method is available.", out
        )
    return Finding(
        "FV-001", "FileVault disk encryption", "Data Protection", "UNKNOWN", "high",
        20, 0, out or "Unable to determine FileVault state.", "Verify FileVault manually or rerun with sufficient local permissions.", out
    )


def check_firewall() -> Finding:
    tool = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    rc, out = run_command([tool, "--getglobalstate"])
    normalized = out.lower()
    if rc == 0 and ("enabled" in normalized or "state = 1" in normalized or "state = 2" in normalized):
        return Finding(
            "FW-001", "Application firewall", "Network Security", "PASS", "medium",
            10, 10, out, "Keep the macOS application firewall enabled and centrally managed where possible.", out
        )
    if "disabled" in normalized or "state = 0" in normalized:
        return Finding(
            "FW-001", "Application firewall", "Network Security", "FAIL", "medium",
            10, 0, out, "Enable the macOS application firewall unless a documented compensating control exists.", out
        )
    return Finding(
        "FW-001", "Application firewall", "Network Security", "UNKNOWN", "medium",
        10, 0, out or "Unable to determine firewall state.", "Verify firewall configuration manually.", out
    )


def check_stealth_mode() -> Finding:
    tool = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    rc, out = run_command([tool, "--getstealthmode"])
    normalized = out.lower()
    if rc == 0 and ("enabled" in normalized or "on" in normalized):
        return Finding(
            "FW-002", "Firewall stealth mode", "Network Security", "PASS", "low",
            5, 5, out, "Keep stealth mode enabled for business laptops when compatible with operational requirements.", out
        )
    if "disabled" in normalized or "off" in normalized:
        return Finding(
            "FW-002", "Firewall stealth mode", "Network Security", "WARN", "low",
            5, 0, out, "Consider enabling stealth mode, especially for laptops used on untrusted networks.", out
        )
    return Finding(
        "FW-002", "Firewall stealth mode", "Network Security", "UNKNOWN", "low",
        5, 0, out or "Unable to determine stealth-mode state.", "Review firewall Options in System Settings.", out
    )


def check_gatekeeper() -> Finding:
    rc, out = run_command(["/usr/sbin/spctl", "--status"])
    normalized = out.lower()
    if "assessments enabled" in normalized:
        return Finding(
            "APP-001", "Gatekeeper assessment", "Application Security", "PASS", "high",
            10, 10, out, "Keep Gatekeeper enabled and prefer notarized software from trusted sources.", out
        )
    if "assessments disabled" in normalized:
        return Finding(
            "APP-001", "Gatekeeper assessment", "Application Security", "FAIL", "high",
            10, 0, out, "Re-enable Gatekeeper using supported System Settings or device-management controls.", out
        )
    return Finding(
        "APP-001", "Gatekeeper assessment", "Application Security", "UNKNOWN", "high",
        10, 0, out or f"spctl returned exit code {rc}.", "Verify Gatekeeper in Privacy & Security settings or through MDM.", out
    )


def check_sip() -> Finding:
    rc, out = run_command(["/usr/bin/csrutil", "status"])
    normalized = out.lower()
    if "enabled" in normalized:
        return Finding(
            "SYS-001", "System Integrity Protection (SIP)", "System Integrity", "PASS", "critical",
            20, 20, out, "Keep System Integrity Protection enabled on standard business endpoints.", out
        )
    if "disabled" in normalized:
        return Finding(
            "SYS-001", "System Integrity Protection (SIP)", "System Integrity", "FAIL", "critical",
            20, 0, out, "Re-enable SIP unless there is a documented, approved business requirement for it to be disabled.", out
        )
    return Finding(
        "SYS-001", "System Integrity Protection (SIP)", "System Integrity", "UNKNOWN", "critical",
        20, 0, out or f"csrutil returned exit code {rc}.", "Verify SIP state from macOS Recovery if necessary.", out
    )


def _read_system_software_update_preferences() -> Dict[str, Optional[bool]]:
    path = Path("/Library/Preferences/com.apple.SoftwareUpdate.plist")
    values: Dict[str, Optional[bool]] = {
        "AutomaticCheckEnabled": None,
        "AutomaticallyInstallMacOSUpdates": None,
        "CriticalUpdateInstall": None,
        "ConfigDataInstall": None,
    }
    try:
        with path.open("rb") as fh:
            data = plistlib.load(fh)
        for key in values:
            value = data.get(key)
            if isinstance(value, bool):
                values[key] = value
            elif isinstance(value, int):
                values[key] = bool(value)
    except Exception:
        pass
    return values


def check_automatic_updates() -> Finding:
    prefs = _read_system_software_update_preferences()
    rc, schedule = run_command(["/usr/sbin/softwareupdate", "--schedule"])
    schedule_lower = schedule.lower()

    auto_check = prefs["AutomaticCheckEnabled"]
    critical = prefs["CriticalUpdateInstall"]
    config_data = prefs["ConfigDataInstall"]
    os_updates = prefs["AutomaticallyInstallMacOSUpdates"]

    if auto_check is None and "automatic checking is on" in schedule_lower:
        auto_check = True
    elif auto_check is None and "automatic checking is off" in schedule_lower:
        auto_check = False

    evidence = (
        f"AutomaticCheckEnabled={auto_check}; "
        f"AutomaticallyInstallMacOSUpdates={os_updates}; "
        f"CriticalUpdateInstall={critical}; ConfigDataInstall={config_data}; "
        f"softwareupdate={schedule or 'no output'}"
    )

    if auto_check is True and critical is not False and config_data is not False:
        points = 15 if os_updates is True else 10
        status = "PASS" if os_updates is True else "WARN"
        observed = "Automatic update checks and security-data installation appear enabled."
        recommendation = (
            "Keep automatic checking and security-data installation enabled. "
            "Consider automatic macOS installation or enforce update deadlines through device management."
        )
        return Finding("UPD-001", "Automatic security updates", "Patch Management", status, "high", 15, points, observed, recommendation, evidence)

    if auto_check is False or critical is False or config_data is False:
        return Finding(
            "UPD-001", "Automatic security updates", "Patch Management", "FAIL", "high",
            15, 0, "One or more automatic security-update controls appear disabled.",
            "Enable automatic update checks and critical/security data installation, preferably through device management.", evidence
        )

    return Finding(
        "UPD-001", "Automatic security updates", "Patch Management", "UNKNOWN", "high",
        15, 0, "The local preference state could not be determined reliably.",
        "Review Software Update settings or the organization's MDM update policy.", evidence
    )


def _defaults_read(domain: str, key: str, current_host: bool = False) -> Optional[str]:
    args = ["/usr/bin/defaults"]
    if current_host:
        args.append("-currentHost")
    args.extend(["read", domain, key])
    rc, out = run_command(args)
    return out.strip() if rc == 0 and out.strip() else None


def check_screen_lock() -> Finding:
    idle_raw = _defaults_read("com.apple.screensaver", "idleTime", current_host=True)
    ask_raw = _defaults_read("com.apple.screensaver", "askForPassword")
    delay_raw = _defaults_read("com.apple.screensaver", "askForPasswordDelay")

    try:
        idle = int(float(idle_raw)) if idle_raw is not None else None
    except ValueError:
        idle = None
    try:
        ask = int(float(ask_raw)) if ask_raw is not None else None
    except ValueError:
        ask = None
    try:
        delay = int(float(delay_raw)) if delay_raw is not None else None
    except ValueError:
        delay = None

    evidence = f"idleTime={idle}; askForPassword={ask}; askForPasswordDelay={delay}"

    # Business baseline: <=15 minutes idle and password required within 5 seconds.
    if idle is not None and 0 < idle <= 900 and ask == 1 and delay is not None and delay <= 5:
        return Finding(
            "ACC-001", "Automatic screen lock", "Access Control", "PASS", "medium",
            10, 10, f"Screen saver idle timeout is {idle} seconds; password requirement is enabled with {delay}-second delay.",
            "Keep a short inactivity timeout and immediate or near-immediate password requirement.", evidence
        )
    if idle == 0 or ask == 0 or (delay is not None and delay > 5) or (idle is not None and idle > 900):
        return Finding(
            "ACC-001", "Automatic screen lock", "Access Control", "WARN", "medium",
            10, 0, "Screen-lock settings do not meet the default business baseline (15 minutes or less; password within 5 seconds).",
            "Set a 15-minute-or-shorter inactivity lock and require the password immediately or within 5 seconds.", evidence
        )
    return Finding(
        "ACC-001", "Automatic screen lock", "Access Control", "UNKNOWN", "medium",
        10, 0, "Could not reliably read all screen-lock preferences; managed settings may override local defaults.",
        "Verify screen-lock policy in System Settings or MDM. Managed Macs should enforce this centrally.", evidence
    )


def check_mdm_enrollment() -> Finding:
    rc, out = run_command(["/usr/bin/profiles", "status", "-type", "enrollment"])
    normalized = out.lower()
    enrolled = "mdm enrollment: yes" in normalized or "enrolled via dep: yes" in normalized
    if enrolled:
        return Finding(
            "MGT-001", "Device management enrollment", "Management", "PASS", "medium",
            10, 10, out, "Keep business endpoints enrolled in approved device management and review enrollment health regularly.", out
        )
    if rc == 0 and ("mdm enrollment: no" in normalized or "enrolled via dep: no" in normalized):
        return Finding(
            "MGT-001", "Device management enrollment", "Management", "WARN", "medium",
            10, 0, out, "For business-managed Macs, enroll the device in an approved MDM/device-management service.", out
        )
    return Finding(
        "MGT-001", "Device management enrollment", "Management", "UNKNOWN", "medium",
        10, 0, out or "Unable to determine MDM enrollment status.", "Verify device-management enrollment manually.", out
    )


def check_admin_group() -> Finding:
    rc, out = run_command(["/usr/bin/dscl", ".", "-read", "/Groups/admin", "GroupMembership"])
    members: List[str] = []
    if rc == 0 and out:
        match = re.search(r"GroupMembership:\s*(.*)", out)
        if match:
            members = [m for m in match.group(1).split() if m]

    current_user = getpass.getuser()
    humanish = [m for m in members if not m.startswith("_") and m not in {"root"}]
    observed = f"Local admin members: {', '.join(humanish) if humanish else 'Unable to enumerate'}"

    if members:
        return Finding(
            "ACC-002", "Local administrator membership", "Access Control", "INFO", "informational",
            0, 0, observed,
            "Review local administrator membership and remove unnecessary standing administrator access. Use separate admin accounts where appropriate.", out
        )
    return Finding(
        "ACC-002", "Local administrator membership", "Access Control", "UNKNOWN", "informational",
        0, 0, observed, "Review local administrator membership manually.", out
    )


def run_all_checks() -> List[Finding]:
    if platform.system() != "Darwin":
        raise RuntimeError("This audit tool must be run on macOS.")

    return [
        check_filevault(),
        check_firewall(),
        check_stealth_mode(),
        check_gatekeeper(),
        check_sip(),
        check_automatic_updates(),
        check_screen_lock(),
        check_mdm_enrollment(),
        check_admin_group(),
    ]
