"""Vulnerability scan: weak system settings an attacker would use, and signs
that the browser was hijacked. Read-only - nothing is changed.

Windows only for now; other platforms return no findings.
"""

from __future__ import annotations

import json
import re
import time

from .core import IS_WINDOWS, Finding, Severity, run_cmd

if IS_WINDOWS:
    import winreg

    from .sysaudit import _reg_get, _reg_values

_PS_QUERY = (
    "$ErrorActionPreference='SilentlyContinue';"
    "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
    "$h=(Get-HotFix|Where-Object{$_.InstalledOn}|Sort-Object InstalledOn -Descending|Select-Object -First 1).InstalledOn;"
    "$u=@(Get-LocalUser|ForEach-Object{[pscustomobject]@{Name=$_.Name;Enabled=[bool]$_.Enabled;"
    "PasswordRequired=[bool]$_.PasswordRequired;Sid=$_.SID.Value}});"
    "@{hotfix=$(if($h){$h.ToString('yyyy-MM-dd')}else{''});users=$u}|ConvertTo-Json -Depth 3 -Compress"
)


def _registry_checks() -> list[Finding]:
    out: list[Finding] = []
    hklm, hkcu, v64 = winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER, winreg.KEY_WOW64_64KEY

    winlogon = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    if str(_reg_get(hklm, winlogon, "AutoAdminLogon", v64)) == "1":
        stored = _reg_get(hklm, winlogon, "DefaultPassword", v64) is not None
        out.append(Finding(
            "vuln-autologon", Severity.HIGH if stored else Severity.LOW,
            "Automatic logon is enabled" + (" and the password is stored in the registry in plain text" if stored else ""),
            "HKLM Winlogon", advice="Turn off automatic sign-in (netplwiz) and change the password if it was stored."))

    if _reg_get(hklm, r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential") == 1:
        out.append(Finding("vuln-wdigest", Severity.HIGH,
                           "WDigest keeps logon passwords in memory in plain text", "HKLM WDigest UseLogonCredential",
                           advice="Set UseLogonCredential to 0. Credential-stealing malware turns this on."))
    if _reg_get(hklm, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1") == 1:
        out.append(Finding("vuln-smb1", Severity.HIGH, "The obsolete SMBv1 protocol is enabled",
                           "LanmanServer SMB1", advice="SMBv1 is what WannaCry spread through. Disable it in Windows Features."))
    if _reg_get(hklm, r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled") == 0:
        out.append(Finding("vuln-secureboot", Severity.MEDIUM, "Secure Boot is turned off", "UEFI firmware",
                           advice="Enable Secure Boot in the firmware settings so boot-level malware cannot load."))
    if _reg_get(hklm, r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL") not in (1, 2):
        out.append(Finding("vuln-lsa", Severity.LOW, "LSA protection is off",
                           "HKLM Lsa RunAsPPL", advice="Enabling it (Windows Security > Device security > Core isolation) "
                                                       "makes password theft from memory much harder."))

    policies = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if _reg_get(hklm, policies, "ConsentPromptBehaviorAdmin", v64) == 0:
        out.append(Finding("vuln-uac-silent", Severity.MEDIUM, "UAC elevates programs to administrator without asking",
                           "ConsentPromptBehaviorAdmin = 0", advice="Raise the UAC slider back to its default level."))
    smart_off = _reg_get(hklm, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", v64) == 0 or \
        str(_reg_get(hklm, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", v64)).lower() == "off"
    if smart_off:
        out.append(Finding("vuln-smartscreen", Severity.MEDIUM, "SmartScreen is turned off",
                           advice="SmartScreen warns about unknown downloads. Turn it back on in Windows Security."))

    if _reg_get(hklm, r"SYSTEM\CurrentControlSet\Services\wuauserv", "Start") == 4:
        out.append(Finding("vuln-updates-disabled", Severity.HIGH, "The Windows Update service is disabled",
                           advice="Without updates known vulnerabilities stay open. Set the service back to Manual."))
    elif _reg_get(hklm, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", v64) == 1:
        out.append(Finding("vuln-updates-manual", Severity.MEDIUM, "Automatic Windows updates are turned off by policy"))

    ts = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
    if _reg_get(hklm, ts, "fDenyTSConnections") == 0 and \
            _reg_get(hklm, ts + r"\WinStations\RDP-Tcp", "UserAuthentication") == 0:
        out.append(Finding("vuln-rdp-nla", Severity.MEDIUM, "Remote Desktop accepts connections without Network Level Authentication",
                           advice="Require NLA in the Remote Desktop settings."))

    macros = []
    for version in ("16.0", "15.0", "14.0"):
        for app in ("Word", "Excel", "PowerPoint"):
            if _reg_get(hkcu, rf"Software\Microsoft\Office\{version}\{app}\Security", "VBAWarnings") == 1:
                macros.append(f"{app} {version}")
    if macros:
        out.append(Finding("vuln-office-macros", Severity.HIGH, "Office runs all macros without warning", "Office Trust Center",
                           macros, "Macros in documents are a top infection route. Set 'Disable all macros with notification'."))

    if _reg_get(hkcu, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt") == 1:
        out.append(Finding("vuln-hidden-extensions", Severity.LOW, "File extensions are hidden in Explorer",
                           advice="A file named 'invoice.pdf.exe' is shown as 'invoice.pdf'. "
                                  "Enable View > Show > File name extensions."))
    return out


def _browser_checks() -> list[Finding]:
    out: list[Finding] = []
    hklm, hkcu = winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER
    inet = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    proxy = _reg_get(hkcu, inet, "ProxyServer")
    if _reg_get(hkcu, inet, "ProxyEnable") == 1 and proxy:
        local = bool(re.search(r"(?:^|=)(?:127\.|localhost|\[::1\])", str(proxy)))
        out.append(Finding("browser-proxy", Severity.MEDIUM,
                           "All web traffic goes through a proxy" + (" run by a program on this PC" if local else ""),
                           str(proxy), advice="If you did not set this up (VPN, corporate network, ad blocker), "
                                              "something is reading your traffic. Remove it in Settings > Network > Proxy."))
    pac = _reg_get(hkcu, inet, "AutoConfigURL")
    if pac:
        out.append(Finding("browser-pac", Severity.MEDIUM, "A proxy auto-config script decides where your traffic goes",
                           str(pac), advice="Malware uses PAC files to redirect banking sites. Remove it if you do not recognise it."))
    forced = []
    for vendor in (r"Google\Chrome", r"Microsoft\Edge", r"BraveSoftware\Brave"):
        for hive, label in ((hklm, "HKLM"), (hkcu, "HKCU")):
            for _name, value in _reg_values(hive, rf"SOFTWARE\Policies\{vendor}\ExtensionInstallForcelist"):
                forced.append(f"{vendor.split(chr(92))[-1]} ({label}): {value}")
    if forced:
        out.append(Finding("browser-forced-extensions", Severity.MEDIUM,
                           "Browser extensions are force-installed by policy and cannot be removed normally",
                           "ExtensionInstallForcelist", forced[:10],
                           "Normal on a company PC. On a personal one this is how adware keeps its extension installed."))
    return out


def _account_checks() -> list[Finding]:
    raw = run_cmd(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _PS_QUERY], timeout=90)
    try:
        data = json.loads(raw) if raw else None
    except ValueError:
        data = None
    if not isinstance(data, dict):
        return [Finding("vuln-accounts-unavailable", Severity.INFO,
                        "Could not read local accounts and update history (PowerShell blocked or timed out)")]
    out: list[Finding] = []
    stamp = str(data.get("hotfix") or "")
    try:
        age = int((time.time() - time.mktime(time.strptime(stamp, "%Y-%m-%d"))) // 86400)
    except ValueError:
        age = -1
    if age > 60:
        out.append(Finding("vuln-updates-old", Severity.MEDIUM,
                           f"No Windows update has been installed for {age} days", f"last update {stamp}",
                           advice="Open Windows Update and install what is pending."))
    users = data.get("users") or []
    if isinstance(users, dict):
        users = [users]
    for u in users:
        if not isinstance(u, dict) or not u.get("Enabled"):
            continue
        name, sid = str(u.get("Name")), str(u.get("Sid") or "")
        if sid.endswith("-501"):
            out.append(Finding("vuln-guest", Severity.MEDIUM, "The Guest account is enabled", name,
                               advice="Disable it: net user Guest /active:no"))
        elif not u.get("PasswordRequired"):
            out.append(Finding("vuln-no-password", Severity.MEDIUM,
                               "Account is allowed to have an empty password", name,
                               advice="Set a password; with file sharing or RDP on, an empty one is an open door. "
                                      "(Can be a false alarm if you sign in with a Microsoft account or a PIN.)"))
        elif sid.endswith("-500"):
            out.append(Finding("vuln-builtin-admin", Severity.LOW, "The built-in Administrator account is enabled", name,
                               advice="It has no lockout and is the first account attackers try. Use a named admin account instead."))
    return out


def audit_hardening() -> list[Finding]:
    if not IS_WINDOWS:
        return [Finding("vuln-unsupported", Severity.INFO, "The vulnerability scan currently supports Windows only")]
    findings: list[Finding] = []
    for part in (_registry_checks, _browser_checks, _account_checks):
        try:
            findings += part()
        except Exception as exc:  # one broken probe must not hide the others
            findings.append(Finding("vuln-error", Severity.INFO, f"{part.__name__} failed: {type(exc).__name__}: {exc}"))
    return findings
