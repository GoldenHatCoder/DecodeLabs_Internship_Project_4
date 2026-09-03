#!/usr/bin/env python3
"""
System Vulnerability Auditor
Project made by M Luqman Shoaib

Windows-first, read-only local security posture auditor.
No third-party Python packages are required.
"""

import csv
import datetime as dt
import json
import os
import platform
import re
import socket
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "System Vulnerability Auditor"
AUTHOR = "M Luqman Shoaib"
VERSION = "3.0"

BG = "#07111b"
PANEL = "#0d1a27"
PANEL2 = "#102333"
BORDER = "#1b3448"
TEXT = "#e8f1f7"
MUTED = "#8fa5b6"
CYAN = "#55d9ff"
GREEN = "#53e3a6"
YELLOW = "#ffd166"
RED = "#ff6b7a"
PURPLE = "#a78bfa"

STATUS_ORDER = {"FAIL": 0, "WARNING": 1, "MANUAL": 2, "INFO": 3, "PASS": 4, "N/A": 5}
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Manual": 5}


def run_cmd(cmd, timeout=20):
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            errors="replace", shell=False
        )
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except Exception as exc:
        return -1, "", str(exc)


def ps(command, timeout=25):
    return run_cmd([
        "powershell", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-Command", command
    ], timeout)


def ps_json(command, timeout=25):
    rc, out, err = ps(command, timeout)
    if rc != 0:
        return None, err or out or f"PowerShell exited with code {rc}."
    if not out:
        return [], ""
    try:
        value = json.loads(out)
        return value, ""
    except Exception as exc:
        return None, f"Could not parse PowerShell JSON: {exc}\n{out[:4000]}"


def norm_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def finding(name, domain, status, severity, evidence, remediation, description=""):
    return {
        "name": name,
        "domain": domain,
        "status": status,
        "severity": severity,
        "evidence": str(evidence).strip() or "No evidence returned.",
        "remediation": remediation,
        "description": description,
        "priority": ("P1" if status == "FAIL" and severity in ("Critical", "High") else
                      "P2" if status == "FAIL" or (status == "WARNING" and severity in ("High", "Medium")) else
                      "P3" if status in ("WARNING", "MANUAL") else "P4"),
        "timestamp": dt.datetime.now().isoformat(timespec="seconds"),
    }


def windows_only(name, domain, remediation):
    return finding(name, domain, "N/A", "Manual", "This check is implemented for Windows.", remediation)


def check_os():
    info = {
        "OS": platform.platform(),
        "Release": platform.release(),
        "Version": platform.version(),
        "Architecture": platform.machine(),
        "Hostname": socket.gethostname(),
        "Python": platform.python_version(),
    }
    return finding("OS & system baseline", "Software & patch management", "INFO", "Info",
                   json.dumps(info, indent=2),
                   "Keep the operating system supported, patched and backed up.",
                   "Records the local platform baseline used by the audit.")


def check_updates():
    if os.name != "nt":
        return windows_only("Pending operating-system updates", "Software & patch management", "Use the platform update manager.")
    command = r"""
$s=New-Object -ComObject Microsoft.Update.Session
$q=$s.CreateUpdateSearcher()
$r=$q.Search('IsInstalled=0 and IsHidden=0')
[pscustomobject]@{Count=$r.Updates.Count; Titles=@($r.Updates | Select-Object -ExpandProperty Title)} | ConvertTo-Json -Compress
"""
    data, err = ps_json(command, 35)
    if data is None:
        return finding("Pending operating-system updates", "Software & patch management", "WARNING", "Medium", err,
                       "Open Windows Update and install pending security and quality updates, then reboot if required.")
    count = int(data.get("Count", 0)) if isinstance(data, dict) else 0
    status = "PASS" if count == 0 else ("FAIL" if count >= 3 else "WARNING")
    severity = "Low" if count == 0 else ("High" if count >= 3 else "Medium")
    return finding("Pending operating-system updates", "Software & patch management", status, severity,
                   json.dumps(data, indent=2),
                   "Install pending updates, reboot if required, and re-run the audit.")


def check_antivirus():
    if os.name != "nt":
        return windows_only("Registered antivirus / endpoint protection", "Software & patch management", "Use the platform security tools.")
    data, err = ps_json("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState,pathToSignedProductExe | ConvertTo-Json -Compress")
    if data is None:
        return finding("Registered antivirus / endpoint protection", "Software & patch management", "WARNING", "Medium", err,
                       "Verify endpoint protection manually.")
    products = norm_list(data)
    if not products:
        return finding("Registered antivirus / endpoint protection", "Software & patch management", "FAIL", "High",
                       "No antivirus product is registered with Windows Security Center.",
                       "Enable supported endpoint protection and confirm that it is active and updating.")
    return finding("Registered antivirus / endpoint protection", "Software & patch management", "PASS", "Low",
                   json.dumps(products, indent=2), "Keep endpoint protection and its definitions up to date.")


def check_defender():
    if os.name != "nt":
        return windows_only("Microsoft Defender protection state", "Software & patch management", "Review endpoint protection manually.")
    data, err = ps_json("Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,AntivirusSignatureAge | ConvertTo-Json -Compress")
    if data is None:
        return finding("Microsoft Defender protection state", "Software & patch management", "MANUAL", "Manual", err,
                       "Open Windows Security and verify real-time protection and signatures.")
    d = data if isinstance(data, dict) else {}
    keys = ["AMServiceEnabled", "AntivirusEnabled", "AntispywareEnabled", "RealTimeProtectionEnabled", "BehaviorMonitorEnabled", "IoavProtectionEnabled", "NISEnabled"]
    enabled = all(bool(d.get(k)) for k in keys if k in d)
    age = d.get("AntivirusSignatureAge")
    if enabled and (age is None or int(age) <= 3):
        status, severity = "PASS", "Low"
    else:
        status, severity = "WARNING", "Medium"
    return finding("Microsoft Defender protection state", "Software & patch management", status, severity,
                   json.dumps(d, indent=2),
                   "Enable real-time protection and update security intelligence. Investigate any protection feature that is disabled.")


def check_password():
    if os.name != "nt":
        return windows_only("Password policy", "Identity & access", "Review the platform password policy.")
    rc, out, err = run_cmd(["net", "accounts"])
    if rc != 0:
        return finding("Password policy", "Identity & access", "WARNING", "Medium", err or out, "Review password policy manually.")
    length = re.search(r"Minimum password length\s+(\d+)", out, re.I)
    age = re.search(r"Maximum password age \(days\)\s+(\d+|Never)", out, re.I)
    n = int(length.group(1)) if length else None
    status = "PASS" if n is not None and n >= 12 else ("FAIL" if n is not None and n < 8 else "WARNING")
    severity = "Low" if status == "PASS" else ("High" if status == "FAIL" else "Medium")
    evidence = out
    if age:
        evidence += f"\nParsed maximum password age: {age.group(1)}"
    return finding("Password policy", "Identity & access", status, severity, evidence,
                   "Use long unique passphrases and an appropriate password policy. Avoid password reuse.")


def check_lockout():
    if os.name != "nt":
        return windows_only("Account lockout policy", "Identity & access", "Review the platform account lockout policy.")
    rc, out, err = run_cmd(["net", "accounts"])
    if rc != 0:
        return finding("Account lockout policy", "Identity & access", "WARNING", "Medium", err or out, "Review account lockout settings manually.")
    attempts = re.search(r"Lockout threshold\s+(\d+|Never)", out, re.I)
    duration = re.search(r"Lockout duration \(minutes\)\s+(\d+|Never)", out, re.I)
    threshold = attempts.group(1) if attempts else "Unknown"
    dur = duration.group(1) if duration else "Unknown"
    good = threshold.isdigit() and 3 <= int(threshold) <= 10
    status = "PASS" if good else "WARNING"
    return finding("Account lockout policy", "Identity & access", status, "Low" if good else "Medium",
                   f"{out}\nParsed threshold: {threshold}\nParsed duration: {dur}",
                   "Use a sensible lockout threshold and duration to reduce password-guessing risk without creating unnecessary denial-of-service risk.")


def check_mfa():
    return finding("Multi-factor authentication", "Identity & access", "MANUAL", "Manual",
                   "MFA is commonly controlled by an external identity provider or account service and cannot be truthfully inferred from a generic local desktop scan.",
                   "Verify MFA is enabled for important accounts. Prefer phishing-resistant methods such as passkeys or security keys where available.")


def check_guest():
    if os.name != "nt":
        return windows_only("Guest account", "Identity & access", "Review guest/temporary accounts manually.")
    rc, out, err = run_cmd(["net", "user", "Guest"])
    if rc != 0:
        return finding("Guest account", "Identity & access", "WARNING", "Medium", err or out, "Review guest account status manually.")
    active = re.search(r"Account active\s+(\w+)", out, re.I)
    enabled = active and active.group(1).lower() == "yes"
    return finding("Guest account", "Identity & access", "FAIL" if enabled else "PASS", "High" if enabled else "Low", out,
                   "Disable the built-in Guest account unless there is a documented business requirement.")


def check_admins():
    if os.name != "nt":
        return windows_only("Local administrator memberships", "Identity & access", "Review privileged memberships manually.")
    rc, out, err = run_cmd(["net", "localgroup", "Administrators"])
    if rc != 0:
        return finding("Local administrator memberships", "Identity & access", "WARNING", "Medium", err or out, "Review administrator memberships manually.")
    members = []
    capture = False
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("---"):
            capture = True
            continue
        if capture and s and "The command completed" not in s:
            members.append(s)
    status = "PASS" if len(members) <= 3 else "WARNING"
    return finding("Local administrator memberships", "Identity & access", status, "Low" if status == "PASS" else "Medium",
                   "\n".join(members) or out,
                   "Remove stale or unnecessary administrator memberships. Use standard accounts for daily work where possible.")


def check_uac():
    if os.name != "nt":
        return windows_only("User Account Control (UAC)", "Identity & access", "Review privilege-elevation controls manually.")
    rc, out, err = run_cmd(["reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "/v", "EnableLUA"])
    if rc != 0:
        return finding("User Account Control (UAC)", "Identity & access", "WARNING", "Medium", err or out, "Verify UAC is enabled.")
    enabled = bool(re.search(r"EnableLUA\s+REG_\w+\s+0x1", out, re.I))
    return finding("User Account Control (UAC)", "Identity & access", "PASS" if enabled else "FAIL", "Low" if enabled else "High", out,
                   "Enable UAC and restart Windows if required to apply a policy change.")


def check_lock():
    if os.name != "nt":
        return windows_only("Automatic screen lock", "Endpoint hygiene", "Verify automatic screen locking manually.")
    a = run_cmd(["reg", "query", r"HKCU\Control Panel\Desktop", "/v", "ScreenSaveActive"])
    t = run_cmd(["reg", "query", r"HKCU\Control Panel\Desktop", "/v", "ScreenSaveTimeOut"])
    active = bool(re.search(r"ScreenSaveActive\s+REG_\w+\s+1", a[1], re.I))
    m = re.search(r"ScreenSaveTimeOut\s+REG_\w+\s+(\d+)", t[1], re.I)
    seconds = int(m.group(1)) if m else 0
    evidence = f"ScreenSaveActive: {active}\nScreenSaveTimeOut: {seconds} seconds"
    if active and 0 < seconds <= 900:
        status, severity = "PASS", "Low"
    elif active:
        status, severity = "WARNING", "Medium"
    else:
        status, severity = "FAIL", "Medium"
    return finding("Automatic screen lock", "Endpoint hygiene", status, severity, evidence,
                   "Enable automatic locking and use a timeout of 15 minutes or less where policy permits.")


def check_firewall():
    if os.name != "nt":
        return windows_only("Host firewall profiles", "Network exposure", "Use the platform firewall tools.")
    data, err = ps_json("Get-NetFirewallProfile | Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress")
    if data is None:
        return finding("Host firewall profiles", "Network exposure", "WARNING", "Medium", err, "Verify firewall status manually.")
    profiles = norm_list(data)
    enabled = all(bool(x.get("Enabled")) for x in profiles)
    return finding("Host firewall profiles", "Network exposure", "PASS" if enabled else "FAIL", "Low" if enabled else "High",
                   json.dumps(profiles, indent=2), "Enable the Windows firewall for applicable network profiles and review exceptions periodically.")


def check_bitlocker():
    if os.name != "nt":
        return windows_only("Disk encryption", "Endpoint hygiene", "Use the platform disk-encryption tools.")
    data, err = ps_json("Get-BitLockerVolume | Select MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod | ConvertTo-Json -Compress")
    if data is None:
        return finding("Disk encryption", "Endpoint hygiene", "MANUAL", "Manual", err, "Verify device encryption or BitLocker manually.")
    vols = [x for x in norm_list(data) if str(x.get("MountPoint", "")).upper().startswith(("C:", "D:"))]
    good = bool(vols) and all(str(x.get("VolumeStatus", "")).replace(" ", "").lower() == "fullyencrypted" and str(x.get("ProtectionStatus", "")).lower() in ("on", "1") for x in vols)
    return finding("Disk encryption", "Endpoint hygiene", "PASS" if good else "WARNING", "Low" if good else "Medium",
                   json.dumps(data, indent=2), "Enable full-disk encryption on supported sensitive volumes and protect recovery material appropriately.")


def check_secure_boot():
    if os.name != "nt":
        return windows_only("Secure Boot", "Endpoint hygiene", "Verify Secure Boot in firmware/Windows Security.")
    data, err = ps_json("try { [pscustomobject]@{SecureBoot=(Confirm-SecureBootUEFI)} } catch { [pscustomobject]@{SecureBoot=$false;Error=$_.Exception.Message} } | ConvertTo-Json -Compress")
    if data is None:
        return finding("Secure Boot", "Endpoint hygiene", "MANUAL", "Manual", err, "Verify Secure Boot in UEFI firmware and Windows System Information.")
    good = bool(data.get("SecureBoot"))
    return finding("Secure Boot", "Endpoint hygiene", "PASS" if good else "WARNING", "Low" if good else "Medium", json.dumps(data, indent=2),
                   "Enable Secure Boot on supported systems after confirming firmware compatibility.")


def check_smb1():
    if os.name != "nt":
        return windows_only("SMBv1 protocol", "Network exposure", "Review legacy SMB protocols manually.")
    data, err = ps_json("Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select FeatureName,State | ConvertTo-Json -Compress")
    if data is None:
        return finding("SMBv1 protocol", "Network exposure", "MANUAL", "Manual", err, "Verify that legacy SMBv1 is disabled unless explicitly required.")
    d = data if isinstance(data, dict) else {}
    state = str(d.get("State", "Unknown"))
    enabled = state.lower() in ("enabled", "enable")
    return finding("SMBv1 protocol", "Network exposure", "FAIL" if enabled else "PASS", "High" if enabled else "Low", json.dumps(d, indent=2),
                   "Disable SMBv1 unless a documented legacy dependency requires it. Test compatibility before removal.")


def check_rdp():
    if os.name != "nt":
        return windows_only("Remote Desktop exposure", "Network exposure", "Review remote-access services manually.")
    reg = run_cmd(["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server", "/v", "fDenyTSConnections"])
    denied = bool(re.search(r"fDenyTSConnections\s+REG_\w+\s+0x1", reg[1], re.I))
    firewall, ferr = ps_json("Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True' | Select DisplayName,Profile,Direction,Action | ConvertTo-Json -Compress")
    evidence = reg[1] or reg[2]
    if firewall is not None:
        evidence += "\n\nEnabled Remote Desktop firewall rules:\n" + json.dumps(firewall, indent=2)
    enabled = not denied
    status = "WARNING" if enabled else "PASS"
    severity = "Medium" if enabled else "Low"
    return finding("Remote Desktop exposure", "Network exposure", status, severity, evidence,
                   "Disable Remote Desktop if it is not required. If required, restrict access with network controls, strong authentication and least privilege.")


def check_powershell_policy():
    if os.name != "nt":
        return windows_only("PowerShell execution policy", "Application hardening", "Review script execution controls manually.")
    data, err = ps_json("Get-ExecutionPolicy -List | Select Scope,ExecutionPolicy | ConvertTo-Json -Compress")
    if data is None:
        return finding("PowerShell execution policy", "Application hardening", "MANUAL", "Manual", err, "Review PowerShell execution policy and organizational application-control policy.")
    policies = norm_list(data)
    unrestricted = [x for x in policies if str(x.get("ExecutionPolicy", "")).lower() in ("unrestricted", "bypass")]
    status = "WARNING" if unrestricted else "PASS"
    return finding("PowerShell execution policy", "Application hardening", status, "Medium" if unrestricted else "Low",
                   json.dumps(policies, indent=2),
                   "Avoid unnecessarily permissive script policies. Use signed scripts, application control and organizational policy where appropriate.")


def check_listeners():
    if os.name != "nt":
        return windows_only("Listening TCP services", "Network exposure", "Use platform network tools to review listening services.")
    data, err = ps_json("Get-NetTCPConnection -State Listen | ForEach-Object { $p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; [pscustomobject]@{LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;PID=$_.OwningProcess;Process=if($p){$p.ProcessName}else{'Unknown'}} } | Sort LocalPort | ConvertTo-Json -Compress")
    if data is None:
        return finding("Listening TCP services", "Network exposure", "WARNING", "Medium", err, "Review listening services and disable unnecessary exposure.")
    listeners = norm_list(data)
    return finding("Listening TCP services", "Network exposure", "WARNING" if len(listeners) > 15 else "PASS", "Medium" if len(listeners) > 15 else "Low",
                   json.dumps(listeners, indent=2), "Review listening services. Disable unnecessary services and restrict required services with the host firewall.")


def check_local_users():
    if os.name != "nt":
        return windows_only("Local user accounts", "Identity & access", "Review local user accounts manually.")
    data, err = ps_json("Get-LocalUser | Select Name,Enabled,LastLogon,PasswordRequired,PasswordExpires,UserMayChangePassword | ConvertTo-Json -Compress")
    if data is None:
        return finding("Local user accounts", "Identity & access", "MANUAL", "Manual", err, "Review local accounts and remove or disable stale accounts.")
    users = norm_list(data)
    enabled = [u for u in users if u.get("Enabled")]
    return finding("Local user accounts", "Identity & access", "INFO", "Info",
                   json.dumps(users, indent=2),
                   "Remove or disable stale accounts and ensure privileged accounts are justified.")


def check_shared_folders():
    if os.name != "nt":
        return windows_only("Network shares", "Network exposure", "Review network shares manually.")
    data, err = ps_json("Get-SmbShare -ErrorAction SilentlyContinue | Select Name,Path,Description,Special,EncryptData | ConvertTo-Json -Compress")
    if data is None:
        return finding("Network shares", "Network exposure", "MANUAL", "Manual", err, "Review network shares and permissions manually.")
    shares = norm_list(data)
    non_special = [s for s in shares if not s.get("Special")]
    status = "WARNING" if non_special else "PASS"
    return finding("Network shares", "Network exposure", status, "Medium" if non_special else "Low",
                   json.dumps(shares, indent=2),
                   "Remove unnecessary shares and review permissions using least privilege. Avoid exposing sensitive folders broadly.")


def check_services():
    if os.name != "nt":
        return windows_only("Automatic services inventory", "System inventory", "Review services manually.")
    data, err = ps_json("Get-CimInstance Win32_Service | Where-Object StartMode -eq 'Auto' | Select Name,DisplayName,State,StartName,PathName | Sort Name | ConvertTo-Json -Compress")
    if data is None:
        return finding("Automatic services inventory", "System inventory", "MANUAL", "Manual", err, "Review automatically starting services and remove unnecessary software.")
    return finding("Automatic services inventory", "System inventory", "INFO", "Info", json.dumps(norm_list(data), indent=2),
                   "Review automatically starting services for software you no longer need. Do not disable security or hardware services without understanding dependencies.")


def check_startup():
    if os.name != "nt":
        return windows_only("Startup programs inventory", "Application hardening", "Review startup applications manually.")
    data, err = ps_json("Get-CimInstance Win32_StartupCommand | Select Name,Command,Location,User | Sort Name | ConvertTo-Json -Compress")
    if data is None:
        return finding("Startup programs inventory", "Application hardening", "MANUAL", "Manual", err, "Review startup applications and remove unknown or unnecessary entries.")
    return finding("Startup programs inventory", "Application hardening", "INFO", "Info", json.dumps(norm_list(data), indent=2),
                   "Review startup applications for unknown, obsolete or unnecessary software.")


def check_shares_and_sessions():
    if os.name != "nt":
        return windows_only("Active SMB sessions", "Network exposure", "Review network sessions manually.")
    data, err = ps_json("Get-SmbSession -ErrorAction SilentlyContinue | Select ClientComputerName,ClientUserName,NumOpens,Dialect,Encrypted,Signed | ConvertTo-Json -Compress")
    if data is None:
        return finding("Active SMB sessions", "Network exposure", "INFO", "Info", err, "Review active file-sharing sessions when troubleshooting unexpected network access.")
    return finding("Active SMB sessions", "Network exposure", "INFO", "Info", json.dumps(norm_list(data), indent=2),
                   "Investigate sessions you do not recognize and keep SMB exposure limited to trusted networks.")


CHECKS = [
    ("OS & system baseline", "Software & patch management", check_os),
    ("Pending operating-system updates", "Software & patch management", check_updates),
    ("Registered antivirus / endpoint protection", "Software & patch management", check_antivirus),
    ("Microsoft Defender protection state", "Software & patch management", check_defender),
    ("Password policy", "Identity & access", check_password),
    ("Account lockout policy", "Identity & access", check_lockout),
    ("Multi-factor authentication", "Identity & access", check_mfa),
    ("Guest account", "Identity & access", check_guest),
    ("Local administrator memberships", "Identity & access", check_admins),
    ("Local user accounts", "Identity & access", check_local_users),
    ("User Account Control (UAC)", "Identity & access", check_uac),
    ("Automatic screen lock", "Endpoint hygiene", check_lock),
    ("Host firewall profiles", "Network exposure", check_firewall),
    ("Disk encryption", "Endpoint hygiene", check_bitlocker),
    ("Secure Boot", "Endpoint hygiene", check_secure_boot),
    ("SMBv1 protocol", "Network exposure", check_smb1),
    ("Remote Desktop exposure", "Network exposure", check_rdp),
    ("PowerShell execution policy", "Application hardening", check_powershell_policy),
    ("Listening TCP services", "Network exposure", check_listeners),
    ("Network shares", "Network exposure", check_shared_folders),
    ("Automatic services inventory", "System inventory", check_services),
    ("Startup programs inventory", "Application hardening", check_startup),
    ("Active SMB sessions", "Network exposure", check_shares_and_sessions),
]


class App(tk.Tk):
    def __init__(self):
        super().__init__(); self.title(f"{APP_NAME}  •  v{VERSION}"); self.geometry("1500x920"); self.minsize(1180,760); self.configure(bg=BG)
        self.results={}; self.running=False; self.scan_started=None; self.scan_finished=None; self.last_score=None; self.last_export=None; self.current_page="dashboard"; self.previous_snapshot=None
        self._build_style(); self._build_ui(); self._show_dashboard()
    def _build_style(self):
        s=ttk.Style(self)
        try:s.theme_use("clam")
        except Exception:pass
        s.configure("TFrame",background=BG); s.configure("TLabel",background=BG,foreground=TEXT,font=("Segoe UI",10)); s.configure("TButton",font=("Segoe UI",9,"bold"),padding=(14,9),borderwidth=0)
        s.configure("Accent.TButton",background="#0d7c9f",foreground="white",padding=(16,10)); s.map("Accent.TButton",background=[("active","#129bc4")])
        s.configure("Dark.TButton",background=PANEL2,foreground=TEXT,padding=(13,9)); s.map("Dark.TButton",background=[("active","#173a4f")])
        s.configure("Treeview",background="#0a1824",foreground=TEXT,fieldbackground="#0a1824",rowheight=34,borderwidth=0,font=("Segoe UI",9)); s.configure("Treeview.Heading",background="#102838",foreground="#b9d1dd",font=("Segoe UI",8,"bold"),relief="flat",padding=(8,8)); s.map("Treeview",background=[("selected","#174c66")],foreground=[("selected","white")])
        s.configure("TCombobox",fieldbackground=PANEL2,background=PANEL2,foreground=TEXT,arrowcolor=CYAN,borderwidth=0,padding=5); s.configure("TNotebook",background=BG,borderwidth=0); s.configure("TNotebook.Tab",background=PANEL2,foreground=MUTED,padding=(14,8)); s.map("TNotebook.Tab",background=[("selected","#17445a")],foreground=[("selected",TEXT)])
    def _build_ui(self):
        self._make_topbar(); shell=tk.Frame(self,bg=BG); shell.pack(fill="both",expand=True); self._make_sidebar(shell); self.main=tk.Frame(shell,bg=BG); self.main.pack(side="left",fill="both",expand=True,padx=(12,24),pady=(12,20))
    def _make_topbar(self):
        top=tk.Frame(self,bg="#08131e",height=76,highlightbackground="#173042",highlightthickness=1); top.pack(fill="x"); top.pack_propagate(False); brand=tk.Frame(top,bg="#08131e");brand.pack(side="left",padx=24,pady=13)
        tk.Label(brand,text="SECURITY OPERATIONS",bg="#08131e",fg=CYAN,font=("Consolas",8,"bold")).pack(anchor="w");tk.Label(brand,text=APP_NAME,bg="#08131e",fg=TEXT,font=("Segoe UI",18,"bold")).pack(anchor="w");tk.Label(top,text=f"v{VERSION}  |  READ-ONLY  |  {AUTHOR}",bg="#08131e",fg=MUTED,font=("Segoe UI",8)).pack(side="right",padx=12);self.top_status=tk.Label(top,text="● READY",bg="#08131e",fg=GREEN,font=("Consolas",9,"bold"));self.top_status.pack(side="right",padx=26)
    def _make_sidebar(self,parent):
        self.sidebar=tk.Frame(parent,bg="#091621",width=205,highlightbackground="#122b3a",highlightthickness=1);self.sidebar.pack(side="left",fill="y",pady=(12,20),padx=(18,0));self.sidebar.pack_propagate(False);tk.Label(self.sidebar,text="WORKSPACE",bg="#091621",fg="#5e7b8d",font=("Consolas",8,"bold")).pack(anchor="w",padx=18,pady=(22,12));self.nav_buttons={}
        for key,label,num in [("dashboard","Dashboard","01"),("findings","Findings","02"),("inventory","Inventory","03"),("reports","Reports","04"),("help","Guide","05")]:
            b=tk.Button(self.sidebar,text=f"  {num}    {label}",anchor="w",bg="#091621",fg=MUTED,activebackground="#123447",activeforeground=TEXT,relief="flat",bd=0,padx=8,pady=12,font=("Segoe UI",10,"bold"),command=lambda k=key:self._navigate(k));b.pack(fill="x",padx=10,pady=2);self.nav_buttons[key]=b
        tk.Frame(self.sidebar,bg="#173143",height=1).pack(fill="x",padx=18,pady=18);tk.Label(self.sidebar,text="DEFENSIVE MODE",bg="#091621",fg=GREEN,font=("Consolas",8,"bold")).pack(anchor="w",padx=18);tk.Label(self.sidebar,text="Local evidence only.\nNo exploit actions.\nNo settings are changed.",bg="#091621",fg=MUTED,justify="left",font=("Segoe UI",8),wraplength=160).pack(anchor="w",padx=18,pady=(7,18));self.side_score=tk.Label(self.sidebar,text="NO AUDIT YET",bg="#091621",fg="#58798b",font=("Consolas",9,"bold"));self.side_score.pack(anchor="w",padx=18,pady=(8,0))
    def _navigate(self,page):
        self.current_page=page;{"dashboard":self._show_dashboard,"findings":self._show_findings,"inventory":self._show_inventory,"reports":self._show_reports,"help":self._show_help}.get(page,self._show_dashboard)();[b.configure(bg="#123447" if k==page else "#091621",fg=TEXT if k==page else MUTED) for k,b in self.nav_buttons.items()]
    def _clear_main(self):[c.destroy() for c in self.main.winfo_children()]
    def _page_header(self,title,subtitle):
        f=tk.Frame(self.main,bg=BG);f.pack(fill="x",pady=(4,14));tk.Label(f,text=title,bg=BG,fg=TEXT,font=("Segoe UI",22,"bold")).pack(anchor="w");tk.Label(f,text=subtitle,bg=BG,fg=MUTED,font=("Segoe UI",9)).pack(anchor="w",pady=(3,0))
    def _panel(self,parent):return tk.Frame(parent,bg=PANEL,highlightbackground="#173246",highlightthickness=1)
    def _card(self,parent,title,value,accent=CYAN,subtitle=""):
        f=tk.Frame(parent,bg=PANEL,highlightbackground="#173246",highlightthickness=1,height=112);f.pack_propagate(False);tk.Frame(f,bg=accent,width=3).pack(side="left",fill="y");body=tk.Frame(f,bg=PANEL);body.pack(side="left",fill="both",expand=True,padx=14,pady=12);tk.Label(body,text=title.upper(),bg=PANEL,fg=MUTED,font=("Segoe UI",8,"bold")).pack(anchor="w");lab=tk.Label(body,text=value,bg=PANEL,fg=accent,font=("Segoe UI",23,"bold"));lab.pack(anchor="w",pady=(2,0));tk.Label(body,text=subtitle,bg=PANEL,fg=MUTED,font=("Segoe UI",8)).pack(anchor="w");return f,lab
    def _score_color(self,score):return MUTED if score is None else (GREEN if score>=85 else YELLOW if score>=70 else RED)
    def _score(self):
        if not self.results:return None
        score=100;weights={"Critical":18,"High":12,"Medium":8,"Low":4}
        for r in self.results.values():score-=weights.get(r["severity"],7) if r["status"]=="FAIL" else max(3,weights.get(r["severity"],5)//2) if r["status"]=="WARNING" else 2 if r["status"]=="MANUAL" else 0
        return max(0,min(100,score))
    def _counts(self):
        c={k:0 for k in ("PASS","WARNING","FAIL","MANUAL","INFO","N/A")}
        for r in self.results.values():c[r["status"]]=c.get(r["status"],0)+1
        return c
    def _risk_counts(self):return {sev:sum(1 for r in self.results.values() if r["severity"]==sev and r["status"] in ("FAIL","WARNING")) for sev in ("Critical","High","Medium","Low")}

    def _show_dashboard(self):
        self._clear_main();self._page_header("Security posture","Score the host, identify exposure, remediate priority items, then verify again.");bar=tk.Frame(self.main,bg=BG);bar.pack(fill="x",pady=(0,14));ttk.Button(bar,text="RUN FULL AUDIT",style="Accent.TButton",command=self.run).pack(side="left");ttk.Button(bar,text="QUICK AUDIT",style="Dark.TButton",command=self.quick_run).pack(side="left",padx=8);ttk.Button(bar,text="EXPORT HTML REPORT",style="Dark.TButton",command=self.export_html).pack(side="left");ttk.Button(bar,text="COMPARE LAST SCAN",style="Dark.TButton",command=self.show_comparison).pack(side="left",padx=8);self.status_var=tk.StringVar(value="Ready — run an audit to collect fresh evidence.");tk.Label(bar,textvariable=self.status_var,bg=BG,fg=MUTED,font=("Segoe UI",9)).pack(side="right")
        cards=tk.Frame(self.main,bg=BG);cards.pack(fill="x",pady=(0,14));score=self._score();counts=self._counts();items=[("Security score",f"{score}/100" if score is not None else "—",self._score_color(score),"Posture estimate"),("High risk",str(counts["FAIL"]),RED,"Controls requiring action"),("Warnings",str(counts["WARNING"]),YELLOW,"Controls to review"),("Manual",str(counts["MANUAL"]),PURPLE,"Needs human verification"),("Controls",str(len(self.results)) if self.results else str(len(CHECKS)),GREEN,"Available audit controls")]
        for i,(t,v,col,sub) in enumerate(items):c,_=self._card(cards,t,v,col,sub);c.pack(side="left",fill="x",expand=True,padx=(0 if i==0 else 8,0))
        grid=tk.Frame(self.main,bg=BG);grid.pack(fill="both",expand=True);left=self._panel(grid);left.pack(side="left",fill="both",expand=True,padx=(0,8));right=self._panel(grid);right.pack(side="right",fill="both",expand=True,padx=(8,0));tk.Label(left,text="PRIORITY QUEUE",bg=PANEL,fg=TEXT,font=("Segoe UI",11,"bold")).pack(anchor="w",padx=16,pady=(15,4));tk.Label(left,text="Highest-impact findings from the latest scan",bg=PANEL,fg=MUTED,font=("Segoe UI",8)).pack(anchor="w",padx=16,pady=(0,10));self.priority_tree=ttk.Treeview(left,columns=("risk","status","finding","domain"),show="headings")
        for col,title,width in [("risk","RISK",80),("status","STATUS",90),("finding","FINDING",330),("domain","DOMAIN",210)]:self.priority_tree.heading(col,text=title);self.priority_tree.column(col,width=width,anchor="w")
        self.priority_tree.pack(fill="both",expand=True,padx=12,pady=(0,12));self.priority_tree.bind("<Double-1>",self._priority_detail);self._refresh_priority();tk.Label(right,text="POSTURE BREAKDOWN",bg=PANEL,fg=TEXT,font=("Segoe UI",11,"bold")).pack(anchor="w",padx=16,pady=(15,8));self.score_canvas=tk.Canvas(right,bg=PANEL,highlightthickness=0,height=185);self.score_canvas.pack(fill="x",padx=16);self._draw_score();self._draw_status_bars(right);tk.Label(right,text="NEXT BEST ACTIONS",bg=PANEL,fg=TEXT,font=("Segoe UI",10,"bold")).pack(anchor="w",padx=16,pady=(15,6));actions=self._recommendations()[:4] or ["Run the first audit to generate prioritized remediation actions."]
        for a in actions:tk.Label(right,text="• "+a,bg=PANEL,fg="#c5d6df",wraplength=440,justify="left",font=("Segoe UI",9)).pack(anchor="w",padx=18,pady=3)
        self._set_nav_score(score)
    def _set_nav_score(self, score):
        """Update the sidebar posture indicator without assuming a previous audit exists."""
        if not hasattr(self, "side_score"):
            return
        if score is None:
            self.side_score.configure(text="NO AUDIT YET", fg="#58798b")
        else:
            self.side_score.configure(text=f"POSTURE  {score:>3}/100", fg=self._score_color(score))

    def _draw_score(self):
        c=self.score_canvas;c.delete("all");score=self._score();c.update_idletasks();x=max(250,c.winfo_width()//2);y=88;c.create_oval(x-62,y-62,x+62,y+62,outline="#17384b",width=12)
        if score is None:c.create_text(x,y,text="NO SCAN",fill=MUTED,font=("Segoe UI",15,"bold"));return
        c.create_arc(x-62,y-62,x+62,y+62,start=90,extent=-max(1,score)*3.6,style="arc",outline=self._score_color(score),width=12);c.create_text(x,y-8,text=str(score),fill=TEXT,font=("Segoe UI",26,"bold"));c.create_text(x,y+24,text="/ 100",fill=MUTED,font=("Consolas",9,"bold"))
    def _draw_status_bars(self,parent):
        counts=self._counts();total=max(1,sum(counts.values()));holder=tk.Frame(parent,bg=PANEL);holder.pack(fill="x",padx=16)
        for label,key,color in [("PASS","PASS",GREEN),("WARNING","WARNING",YELLOW),("FAIL","FAIL",RED),("MANUAL","MANUAL",PURPLE)]:
            row=tk.Frame(holder,bg=PANEL);row.pack(fill="x",pady=2);tk.Label(row,text=label,bg=PANEL,fg=MUTED,width=9,anchor="w",font=("Consolas",8,"bold")).pack(side="left");pc=tk.Canvas(row,bg="#102330",height=7,highlightthickness=0);pc.pack(side="left",fill="x",expand=True,padx=6);pc.update_idletasks();w=max(1,pc.winfo_width());pc.create_rectangle(0,0,w*counts[key]/total,7,fill=color,outline="");tk.Label(row,text=str(counts[key]),bg=PANEL,fg=TEXT,width=4,anchor="e",font=("Consolas",8,"bold")).pack(side="right")
    def _refresh_priority(self):
        if not hasattr(self,"priority_tree"):return
        for i in self.priority_tree.get_children():self.priority_tree.delete(i)
        rows=sorted([r for r in self.results.values() if r["status"] in ("FAIL","WARNING","MANUAL")],key=lambda r:(SEVERITY_ORDER.get(r["severity"],9),STATUS_ORDER.get(r["status"],9)))[:15]
        for r in rows:self.priority_tree.insert("","end",iid=r["name"],values=(r["severity"],r["status"],r["name"],r["domain"]))
    def _priority_detail(self,_=None):
        sel=self.priority_tree.selection()
        if sel:self._navigate("findings");self.after(80,lambda:self._select_finding(sel[0]))

    def _show_findings(self):
        self._clear_main();self._page_header("Findings & evidence","Filter by risk, domain or keyword. Every result includes evidence and a remediation path.");toolbar=tk.Frame(self.main,bg=BG);toolbar.pack(fill="x",pady=(0,10));self.search_var=tk.StringVar();e=tk.Entry(toolbar,textvariable=self.search_var,bg="#0e2230",fg=TEXT,insertbackground=TEXT,relief="flat",font=("Segoe UI",10),width=30);e.pack(side="left",ipady=8,padx=(0,8));e.bind("<KeyRelease>",lambda _:self._populate_findings());self.filter_var=tk.StringVar(value="All");fc=ttk.Combobox(toolbar,textvariable=self.filter_var,values=["All","FAIL","WARNING","MANUAL","PASS","INFO","N/A"],state="readonly",width=11);fc.pack(side="left");fc.bind("<<ComboboxSelected>>",lambda _:self._populate_findings());self.domain_var=tk.StringVar(value="All domains");dc=ttk.Combobox(toolbar,textvariable=self.domain_var,values=["All domains"]+sorted({r["domain"] for r in self.results.values()}),state="readonly",width=26);dc.pack(side="left",padx=8);dc.bind("<<ComboboxSelected>>",lambda _:self._populate_findings());ttk.Button(toolbar,text="COPY FINDING",style="Dark.TButton",command=self.copy_selected).pack(side="right")
        paned=tk.PanedWindow(self.main,orient="horizontal",bg=BG,sashwidth=5,bd=0);paned.pack(fill="both",expand=True);lf=self._panel(paned);rf=self._panel(paned);paned.add(lf,minsize=590);paned.add(rf,minsize=390);self.findings_tree=ttk.Treeview(lf,columns=("status","severity","domain","finding"),show="headings")
        for col,title,width in [("status","STATUS",85),("severity","SEVERITY",85),("domain","DOMAIN",200),("finding","FINDING",340)]:self.findings_tree.heading(col,text=title);self.findings_tree.column(col,width=width,anchor="w")
        self.findings_tree.pack(fill="both",expand=True,padx=10,pady=10);self.findings_tree.bind("<<TreeviewSelect>>",lambda _:self._render_detail());self.detail_title=tk.Label(rf,text="SELECT A FINDING",bg=PANEL,fg=TEXT,font=("Segoe UI",13,"bold"),wraplength=430,justify="left");self.detail_title.pack(anchor="w",padx=16,pady=(15,8));self.detail_text=tk.Text(rf,bg="#081620",fg="#c9d7df",insertbackground=TEXT,relief="flat",wrap="word",font=("Consolas",9),padx=14,pady=14);self.detail_text.pack(fill="both",expand=True,padx=12,pady=(0,12));self.detail_text.config(state="disabled");self._populate_findings()
    def _populate_findings(self):
        if not hasattr(self,"findings_tree"):return
        for i in self.findings_tree.get_children():self.findings_tree.delete(i)
        q=self.search_var.get().strip().lower();status=self.filter_var.get();domain=self.domain_var.get();rows=[]
        for r in self.results.values():
            if q and q not in f"{r['name']} {r['domain']} {r['severity']} {r['evidence']} {r['remediation']}".lower():continue
            if status!="All" and r["status"]!=status:continue
            if domain!="All domains" and r["domain"]!=domain:continue
            rows.append(r)
        rows.sort(key=lambda r:(STATUS_ORDER.get(r["status"],9),SEVERITY_ORDER.get(r["severity"],9),r["name"]));[self.findings_tree.insert("","end",iid=r["name"],values=(r["status"],r["severity"],r["domain"],r["name"])) for r in rows]
        if rows:self.findings_tree.selection_set(rows[0]["name"]);self._render_detail()
        else:self._set_detail("No findings match the current filters.")
    def _select_finding(self,name):
        if hasattr(self,"findings_tree") and name in self.findings_tree.get_children():self.findings_tree.selection_set(name);self.findings_tree.focus(name);self.findings_tree.see(name);self._render_detail()
    def _set_detail(self,text):self.detail_text.config(state="normal");self.detail_text.delete("1.0","end");self.detail_text.insert("1.0",text);self.detail_text.config(state="disabled")
    def _render_detail(self):
        sel=self.findings_tree.selection()
        if not sel:return
        r=self.results.get(sel[0]);
        if not r:return
        self.detail_title.config(text=r["name"]);self._set_detail(f"STATUS       {r['status']}\nSEVERITY     {r['severity']}\nDOMAIN       {r['domain']}\nCOLLECTED    {r['timestamp']}\n\nDESCRIPTION\n{r['description'] or 'Local security control check.'}\n\nEVIDENCE\n{r['evidence']}\n\nREMEDIATION\n{r['remediation']}")
    def copy_selected(self):
        if not hasattr(self,"findings_tree") or not self.findings_tree.selection():messagebox.showinfo(APP_NAME,"Select a finding first.");return
        r=self.results[self.findings_tree.selection()[0]];self.clipboard_clear();self.clipboard_append(f"{r['name']} | {r['status']} | {r['severity']}\n\nEvidence:\n{r['evidence']}\n\nRemediation:\n{r['remediation']}");self.update();self.status_var.set("Finding copied to clipboard.")

    def _show_inventory(self):
        self._clear_main();self._page_header("Security inventory","Operational visibility from the latest scan. Inventory entries are informational, not automatic vulnerabilities.");tabs=ttk.Notebook(self.main);tabs.pack(fill="both",expand=True)
        for label,check_name in [("TCP listeners","Listening TCP services"),("Local users","Local user accounts"),("Services","Automatic services inventory"),("Startup","Startup programs inventory"),("Shares","Network shares"),("SMB sessions","Active SMB sessions")]:
            frame=tk.Frame(tabs,bg=PANEL);tabs.add(frame,text=label);r=self.results.get(check_name);txt=tk.Text(frame,bg="#081620",fg="#c9d7df",relief="flat",wrap="none",font=("Consolas",9),padx=14,pady=14);txt.pack(fill="both",expand=True,padx=10,pady=10);txt.insert("1.0",r["evidence"] if r else "Run an audit first to populate this inventory.");txt.config(state="disabled")

    def _recommendations(self):
        rows=sorted([r for r in self.results.values() if r["status"] in ("FAIL","WARNING")],key=lambda r:(SEVERITY_ORDER.get(r["severity"],9),STATUS_ORDER.get(r["status"],9)));return [f"{r['name']}: {r['remediation']}" for r in rows]
    def _comparison_data(self):
        previous=self.previous_snapshot
        if not previous:return {"available":False,"score_delta":None,"improved":[],"worsened":[],"unchanged":0}
        oldmap={x["name"]:x for x in previous.get("checks",[])}; improved=[]; worsened=[]; unchanged=0
        for name,r in self.results.items():
            o=oldmap.get(name)
            if not o:continue
            old=STATUS_ORDER.get(o.get("status"),9); new=STATUS_ORDER.get(r.get("status"),9)
            if new>old:improved.append((name,o.get("status"),r.get("status")))
            elif new<old:worsened.append((name,o.get("status"),r.get("status")))
            else:unchanged+=1
        old_score=previous.get("posture_score")
        return {"available":True,"score_delta":(self._score()-old_score) if isinstance(old_score,(int,float)) and self._score() is not None else None,"previous_score":old_score,"improved":improved,"worsened":worsened,"unchanged":unchanged}
    def _report_payload(self):
        duration=round((self.scan_finished-self.scan_started).total_seconds(),2) if self.scan_started and self.scan_finished else None;return {"application":APP_NAME,"version":VERSION,"author":AUTHOR,"generated":dt.datetime.now().isoformat(timespec="seconds"),"computer":socket.gethostname(),"operating_system":platform.platform(),"scan_started":self.scan_started.isoformat(timespec="seconds") if self.scan_started else None,"scan_finished":self.scan_finished.isoformat(timespec="seconds") if self.scan_finished else None,"scan_duration_seconds":duration,"posture_score":self._score(),"counts":self._counts(),"risk_counts":self._risk_counts(),"recommendations":self._recommendations(),"comparison":self._comparison_data(),"checks":list(self.results.values())}
    def _save_snapshot(self):
        folder=os.path.join(os.path.dirname(os.path.abspath(__file__)),"reports");os.makedirs(folder,exist_ok=True)
        try:
            with open(os.path.join(folder,"last_scan.json"),"w",encoding="utf-8") as f:json.dump(self._report_payload(),f,indent=2,default=str)
        except Exception:pass
    def _ensure_results(self):
        if not self.results:messagebox.showinfo(APP_NAME,"Run an audit first.");return False
        return True
    def _html_report(self,p):
        import html as _html
        c=p["counts"];score=p["posture_score"];color=self._score_color(score);findings=sorted(p["checks"],key=lambda r:(SEVERITY_ORDER.get(r["severity"],9),STATUS_ORDER.get(r["status"],9),r["name"]));rows=[];details=[]
        for r in findings:
            name=_html.escape(r["name"]);domain=_html.escape(r["domain"]);status=_html.escape(r["status"]);sev=_html.escape(r["severity"]);cls=status.lower().replace("/","-");rows.append(f"<tr><td><b>{_html.escape(r.get('priority','P4'))}</b></td><td><b>{sev}</b></td><td><span class='pill {cls}'>{status}</span></td><td>{domain}</td><td><b>{name}</b><br><span class='muted'>{_html.escape(r['description'] or '')}</span></td></tr>");details.append(f"<section class='finding'><div class='finding-head'><h3>{name}</h3><span class='pill {cls}'>{status}</span></div><p><b>Priority:</b> {_html.escape(r.get('priority','P4'))} &nbsp; <b>Domain:</b> {domain} &nbsp; <b>Severity:</b> {sev}</p><h4>Evidence</h4><pre>{_html.escape(r['evidence'][:20000])}</pre><h4>Recommended remediation</h4><p>{_html.escape(r['remediation'])}</p></section>")
        recs=''.join(f"<li>{_html.escape(x)}</li>" for x in p["recommendations"][:10]) or '<li>No FAIL/WARNING findings were generated.</li>'
        return f'''<!doctype html><html><head><meta charset="utf-8"><title>{APP_NAME} Report</title><style>body{{margin:0;background:#07111b;color:#e8f1f7;font:14px Segoe UI,Arial,sans-serif}}.wrap{{max-width:1180px;margin:auto;padding:34px}}.hero{{background:#0d1a27;border:1px solid #1b3448;padding:28px;border-radius:16px}}h1{{margin:0 0 8px;font-size:30px}}h2{{margin-top:30px}}h3{{margin:0}}.muted{{color:#8fa5b6}}.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:18px 0}}.card{{background:#0d1a27;border:1px solid #1b3448;border-radius:12px;padding:18px}}.num{{font-size:28px;font-weight:700;margin-top:5px}}.score{{font-size:52px;font-weight:800;color:{color}}}.pill{{display:inline-block;padding:4px 8px;border-radius:999px;font:11px Consolas,monospace;font-weight:700}}.pass{{background:#123a2e;color:#53e3a6}}.warning{{background:#453a15;color:#ffd166}}.fail{{background:#461d27;color:#ff6b7a}}.manual{{background:#302452;color:#a78bfa}}.info{{background:#193040;color:#8fdcff}}.n-a{{background:#26313a;color:#b6c1c8}}table{{width:100%;border-collapse:collapse;background:#0d1a27;border:1px solid #1b3448}}th,td{{padding:12px;border-bottom:1px solid #173246;text-align:left;vertical-align:top}}th{{color:#9fb6c4;font-size:11px}}pre{{background:#081620;border:1px solid #163143;border-radius:10px;padding:14px;white-space:pre-wrap;overflow:auto;color:#cbd9e2}}.finding{{background:#0d1a27;border:1px solid #1b3448;border-radius:12px;padding:18px;margin:12px 0}}.finding-head{{display:flex;justify-content:space-between;gap:10px;align-items:center}}li{{margin:8px 0}}.footer{{color:#718b9b;margin-top:30px;font-size:12px}}@media(max-width:900px){{.grid{{grid-template-columns:repeat(2,1fr)}}}}</style></head><body><div class="wrap"><div class="hero"><div class="muted">DEFENSIVE SECURITY AUDIT</div><h1>{APP_NAME}</h1><div class="muted">Project made by {AUTHOR} · v{VERSION}</div><div class="score">{score}/100</div><div>Security posture score based on controls collected during this local audit.</div></div><div class="grid"><div class="card">CONTROLS<div class="num">{len(p['checks'])}</div></div><div class="card">PASS<div class="num">{c['PASS']}</div></div><div class="card">WARNINGS<div class="num">{c['WARNING']}</div></div><div class="card">FAIL<div class="num">{c['FAIL']}</div></div><div class="card">MANUAL<div class="num">{c['MANUAL']}</div></div></div><h2>Executive summary</h2><div class="hero"><p><b>Computer:</b> {_html.escape(p['computer'])}</p><p><b>Operating system:</b> {_html.escape(p['operating_system'])}</p><p><b>Generated:</b> {_html.escape(p['generated'])}</p><p><b>Scan duration:</b> {p['scan_duration_seconds']} seconds</p><p>This report separates verified local evidence from controls that require human or external verification.</p></div><h2>Risk overview</h2><div class="grid"><div class="card">CRITICAL<div class="num">{p['risk_counts']['Critical']}</div></div><div class="card">HIGH<div class="num">{p['risk_counts']['High']}</div></div><div class="card">MEDIUM<div class="num">{p['risk_counts']['Medium']}</div></div><div class="card">LOW<div class="num">{p['risk_counts']['Low']}</div></div><div class="card">SCORE DELTA<div class="num">{('+' if p['comparison'].get('score_delta',0)>0 else '') + str(p['comparison'].get('score_delta')) if p['comparison'].get('score_delta') is not None else '—'}</div></div></div><h2>Priority remediation plan</h2><div class="hero"><ol>{recs}</ol></div><h2>Findings summary</h2><table><thead><tr><th>Priority</th><th>Severity</th><th>Status</th><th>Domain</th><th>Finding</th></tr></thead><tbody>{''.join(rows)}</tbody></table><h2>Detailed evidence & remediation</h2>{''.join(details)}<h2>Scan-to-scan verification</h2><div class="hero"><p><b>Previous score:</b> {p['comparison'].get('previous_score','—')} &nbsp; <b>Current score:</b> {score} &nbsp; <b>Delta:</b> {('+' if p['comparison'].get('score_delta',0)>0 else '') + str(p['comparison'].get('score_delta')) if p['comparison'].get('score_delta') is not None else '—'}</p><p><b>Improved controls:</b> {len(p['comparison'].get('improved',[]))} &nbsp; <b>Worsened controls:</b> {len(p['comparison'].get('worsened',[]))} &nbsp; <b>Unchanged:</b> {p['comparison'].get('unchanged',0)}</p></div><h2>Verification workflow</h2><div class="hero"><p><b>1. Review</b> evidence. <b>2. Remediate</b> using approved procedures. <b>3. Re-scan</b> the endpoint. <b>4. Compare</b> the new result with the previous scan. <b>5. Archive</b> the report.</p><p>The application itself is read-only and does not change firewall rules, accounts, passwords, encryption, or other security settings.</p></div><div class="footer">Do not place passwords, MFA codes, recovery keys, tokens or other secrets in exported reports. Audit only systems you own or are explicitly authorized to assess.</div></div></body></html>'''

    def _show_reports(self):
        self._clear_main();self._page_header("Reports & verification","Generate evidence-rich reports for coursework, remediation tracking and security reviews.");panel=self._panel(self.main);panel.pack(fill="both",expand=True);tk.Label(panel,text="REPORT CENTER",bg=PANEL,fg=TEXT,font=("Segoe UI",12,"bold")).pack(anchor="w",padx=22,pady=(20,4));tk.Label(panel,text="HTML is the primary human-readable report. JSON and CSV are structured outputs for analysis.",bg=PANEL,fg=MUTED,font=("Segoe UI",9)).pack(anchor="w",padx=22,pady=(0,18));buttons=tk.Frame(panel,bg=PANEL);buttons.pack(anchor="w",padx=22)
        for text,fn,style in [("EXPORT HTML REPORT",self.export_html,"Accent.TButton"),("EXPORT MARKDOWN",self.export_markdown,"Dark.TButton"),("EXPORT JSON",self.export_json,"Dark.TButton"),("EXPORT CSV",self.export_csv,"Dark.TButton")]:ttk.Button(buttons,text=text,command=fn,style=style).pack(side="left",padx=(0,8))
        tk.Frame(panel,bg="#173246",height=1).pack(fill="x",padx=22,pady=22)
        for title,desc in [("Executive summary","Score, scan metadata, status counts and host identity."),("Risk prioritization","Findings sorted by severity and remediation priority."),("Evidence appendix","Raw local evidence for every control, preserved for review."),("Remediation plan","Action-oriented recommendations for each failed or warning control."),("Verification workflow","Designed for re-scan and before/after comparison after hardening.")]:
            row=tk.Frame(panel,bg=PANEL);row.pack(fill="x",padx=22,pady=7);tk.Label(row,text="✓",bg=PANEL,fg=GREEN,font=("Segoe UI",12,"bold"),width=3).pack(side="left");tk.Label(row,text=title,bg=PANEL,fg=TEXT,font=("Segoe UI",9,"bold"),width=22,anchor="w").pack(side="left");tk.Label(row,text=desc,bg=PANEL,fg=MUTED,font=("Segoe UI",9),anchor="w").pack(side="left",fill="x",expand=True)
        tk.Label(panel,text="Tip: export HTML for a polished browser-ready report you can submit or attach to a project.",bg=PANEL,fg=CYAN,font=("Segoe UI",9,"bold")).pack(anchor="w",padx=22,pady=24)
    def show_comparison(self):
        if not self._ensure_results():return
        previous=self.previous_snapshot
        if previous is None:
            path=os.path.join(os.path.dirname(os.path.abspath(__file__)),"reports","last_scan.json")
            try:
                if os.path.exists(path):
                    with open(path,"r",encoding="utf-8") as f:previous=json.load(f)
            except Exception:previous=None
        if not previous:messagebox.showinfo(APP_NAME,"No previous scan snapshot is available yet. Run another audit after remediation to create a comparison.");return
        oldmap={x["name"]:x for x in previous.get("checks",[])};improved=[];worsened=[];unchanged=[]
        for name,r in self.results.items():
            o=oldmap.get(name)
            if not o:continue
            if STATUS_ORDER.get(r["status"],9)>STATUS_ORDER.get(o["status"],9):improved.append((name,o["status"],r["status"]))
            elif STATUS_ORDER.get(r["status"],9)<STATUS_ORDER.get(o["status"],9):worsened.append((name,o["status"],r["status"]))
            else:unchanged.append(name)
        msg=f"CURRENT SCORE: {self._score()}/100\nPREVIOUS SCORE: {previous.get('posture_score','—')}/100\n\nIMPROVED ({len(improved)})\n"+"\n".join(f"• {n}: {a} → {b}" for n,a,b in improved[:12]);msg+=f"\n\nWORSENED ({len(worsened)})\n"+"\n".join(f"• {n}: {a} → {b}" for n,a,b in worsened[:12]);msg+=f"\n\nUNCHANGED: {len(unchanged)}"
        win=tk.Toplevel(self);win.title("Scan comparison");win.geometry("760x600");win.configure(bg=BG);tk.Label(win,text="BEFORE / AFTER COMPARISON",bg=BG,fg=CYAN,font=("Consolas",10,"bold")).pack(anchor="w",padx=20,pady=(20,4));tk.Label(win,text=f"Previous: {previous.get('generated','unknown')}  →  Current: {dt.datetime.now().isoformat(timespec='seconds')}",bg=BG,fg=MUTED,font=("Segoe UI",9)).pack(anchor="w",padx=20);t=tk.Text(win,bg="#081620",fg="#c9d7df",relief="flat",wrap="word",font=("Consolas",9),padx=16,pady=16);t.pack(fill="both",expand=True,padx=20,pady=18);t.insert("1.0",msg);t.config(state="disabled")
    def export_html(self):
        if not self._ensure_results():return
        path=filedialog.asksaveasfilename(defaultextension=".html",initialfile="security-audit-report.html",filetypes=[("HTML report","*.html")]);
        if not path:return
        with open(path,"w",encoding="utf-8") as f:f.write(self._html_report(self._report_payload()));self.last_export=path;messagebox.showinfo(APP_NAME,f"HTML report saved to:\n{path}")
    def export_markdown(self):
        if not self._ensure_results():return
        path=filedialog.asksaveasfilename(defaultextension=".md",initialfile="security-audit-report.md",filetypes=[("Markdown","*.md")]);
        if not path:return
        p=self._report_payload();c=p["counts"];lines=["# System Vulnerability Report","",f"**Project made by:** {AUTHOR}",f"**Application:** {APP_NAME} v{VERSION}",f"**Generated:** {p['generated']}",f"**Computer:** {p['computer']}",f"**Operating system:** {p['operating_system']}",f"**Scan duration:** {p['scan_duration_seconds']} seconds",f"**Posture score:** {p['posture_score']}/100","","## Executive Summary","",f"- Controls checked: {len(self.results)}",f"- PASS: {c['PASS']}",f"- WARNING: {c['WARNING']}",f"- FAIL: {c['FAIL']}",f"- MANUAL: {c['MANUAL']}",f"- INFO: {c['INFO']}","","## Priority Remediation Plan",""];lines += [f"{i}. {r}" for i,r in enumerate(p["recommendations"][:10],1)] or ["No FAIL/WARNING remediation items were generated."];lines += ["","## Findings",""]
        for r in sorted(self.results.values(),key=lambda x:(SEVERITY_ORDER.get(x["severity"],9),STATUS_ORDER.get(x["status"],9))):lines += [f"### {r['name']}",f"- **Priority:** {r.get('priority','P4')}",f"- **Domain:** {r['domain']}",f"- **Status:** {r['status']}",f"- **Severity:** {r['severity']}","",r['description'] or "Local security control check.","","**Evidence:**","```text",r['evidence'][:20000],"```","","**Remediation:**",r['remediation'],""]
        lines += ["## Verification","","Run the application again after approved remediation and compare the new score/findings.","","## Safety","","Use only on systems you own or are authorized to assess. Never include passwords, MFA codes, recovery keys or tokens in reports."]
        with open(path,"w",encoding="utf-8") as f:f.write("\n".join(lines));self.last_export=path;messagebox.showinfo(APP_NAME,f"Markdown report saved to:\n{path}")
    def export_json(self):
        if not self._ensure_results():return
        path=filedialog.asksaveasfilename(defaultextension=".json",initialfile="security-audit-report.json",filetypes=[("JSON","*.json")]);
        if not path:return
        with open(path,"w",encoding="utf-8") as f:json.dump(self._report_payload(),f,indent=2,default=str);self.last_export=path;messagebox.showinfo(APP_NAME,f"JSON report saved to:\n{path}")
    def export_csv(self):
        if not self._ensure_results():return
        path=filedialog.asksaveasfilename(defaultextension=".csv",initialfile="security-audit-findings.csv",filetypes=[("CSV","*.csv")]);
        if not path:return
        fields=["name","domain","status","severity","priority","timestamp","remediation","evidence"]
        with open(path,"w",newline="",encoding="utf-8-sig") as f:
            w=csv.DictWriter(f,fieldnames=fields);w.writeheader();[w.writerow({k:r.get(k,"") for k in fields}) for r in self.results.values()]
        self.last_export=path;messagebox.showinfo(APP_NAME,f"CSV report saved to:\n{path}")
    def _show_help(self):
        self._clear_main();self._page_header("Guide","Use the auditor as a repeatable defensive workflow, not as a one-click security guarantee.");panel=self._panel(self.main);panel.pack(fill="both",expand=True);text=("HOW TO USE\n\n1. Run FULL AUDIT for the complete control set.\n2. Open Findings and filter FAIL/WARNING.\n3. Read the evidence before making any change.\n4. Apply approved remediation outside this application.\n5. Run the audit again and use COMPARE LAST SCAN.\n6. Export HTML for a polished report; JSON/CSV are useful for structured analysis.\n\nWHY SOME RESULTS ARE MANUAL\n\nCertain security properties depend on external identity providers, organization policy, firmware or context that a generic local scan cannot prove. The application intentionally reports MANUAL instead of guessing.\n\nSCORE INTERPRETATION\n\nThe score is a prioritization aid based on observed control results. It is not a CVSS score, compliance certification, or guarantee that the computer is secure.\n\nSAFE USE\n\nThe application is read-only. It does not exploit vulnerabilities, change passwords, modify firewall rules, disable accounts, or alter encryption settings. Run it only on systems you own or are explicitly authorized to assess.");t=tk.Text(panel,bg="#081620",fg="#c9d7df",relief="flat",wrap="word",font=("Segoe UI",10),padx=22,pady=22);t.pack(fill="both",expand=True,padx=12,pady=12);t.insert("1.0",text);t.config(state="disabled")
    def run(self):self._start_scan(full=True)
    def quick_run(self):self._start_scan(full=False)
    def _start_scan(self,full=True):
        if self.running:return
        quick={"OS & system baseline","Pending operating-system updates","Registered antivirus / endpoint protection","Microsoft Defender protection state","Password policy","Account lockout policy","Multi-factor authentication","Guest account","Local administrator memberships","User Account Control (UAC)","Automatic screen lock","Host firewall profiles","Disk encryption","SMBv1 protocol","Remote Desktop exposure","Listening TCP services"};selected=CHECKS if full else [x for x in CHECKS if x[0] in quick]
        self.previous_snapshot=None
        snapshot=os.path.join(os.path.dirname(os.path.abspath(__file__)),"reports","last_scan.json")
        try:
            if os.path.exists(snapshot):
                with open(snapshot,"r",encoding="utf-8") as f:self.previous_snapshot=json.load(f)
        except Exception:self.previous_snapshot=None
        self.results={};self.running=True;self.scan_started=dt.datetime.now();self._navigate("dashboard");self.top_status.config(text="● SCANNING",fg=CYAN);self.status_var.set("Scanning local security controls…");threading.Thread(target=self._scan_worker,args=(selected,),daemon=True).start()
    def _scan_worker(self,checks):
        for i,(name,domain,fn) in enumerate(checks,1):
            try:result=fn()
            except Exception as exc:result=finding(name,domain,"WARNING","Medium",f"Unhandled check error: {exc}","Review this control manually.")
            self.results[name]=result;self.after(0,self._scan_progress,i,len(checks),name)
        self.scan_finished=dt.datetime.now();self.running=False;self.after(0,self._scan_done)
    def _scan_progress(self,i,total,name):self.status_var.set(f"Scanning {i}/{total}  ·  {name}");self.top_status.config(text=f"● {i}/{total} SCANNING",fg=CYAN)
    def _scan_done(self):
        score=self._score();counts=self._counts();self.last_score=score;self._save_snapshot();self.top_status.config(text="● AUDIT COMPLETE",fg=GREEN);self.status_var.set(f"Audit complete  ·  {len(self.results)} controls  ·  posture {score}/100");self._show_dashboard();messagebox.showinfo(APP_NAME,f"Audit complete.\n\nPosture score: {score}/100\nFAIL: {counts['FAIL']}\nWARNING: {counts['WARNING']}\nMANUAL: {counts['MANUAL']}\n\nUse Findings to inspect evidence and Reports to export the assessment.")

if __name__ == "__main__":App().mainloop()
