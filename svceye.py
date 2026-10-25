import re
import subprocess
import argparse
import os
import time

RED = "\033[0;31m"
RESET = "\033[0;0m"
PURPLE = "\033[0;35m"
BOLD = "\033[1m"
LIGHT_CYAN = "\033[1;36m"
LIGHT_PURPLE = "\033[1;35m"

banner = f"""
{RED}
  ██████ ██▒   █▓ ▄████▄  ▓█████▓██   ██▓▓█████ 
▒██    ▒▓██░   █▒▒██▀ ▀█  ▓█   ▀ ▒██  ██▒▓█   ▀ 
░ ▓██▄   ▓██  █▒░▒▓█    ▄ ▒███    ▒██ ██░▒███   
  ▒   ██▒ ▒██ █░░▒▓▓▄ ▄██▒▒▓█  ▄  ░ ▐██▓░▒▓█  ▄ 
▒██████▒▒  ▒▀█░  ▒ ▓███▀ ░░▒████▒ ░ ██▒▓░░▒████▒
▒ ▒▓▒ ▒ ░  ░ ▐░  ░ ░▒ ▒  ░░░ ▒░ ░  ██▒▒▒ ░░ ▒░ ░
░ ░▒  ░ ░  ░ ░░    ░  ▒    ░ ░  ░▓██ ░▒░  ░ ░  ░
░  ░  ░      ░░  ░           ░   ▒ ▒ ░░     ░   
      ░       ░  ░ ░         ░  ░░ ░        ░  ░
             ░   ░               ░ ░            
            
            {BOLD}Github: Exotic132
            
{RESET}
"""
print(banner)

parser = argparse.ArgumentParser(prog='svceye.py', usage="%(prog)s [options]",)
parser.add_argument("-a", "--all", action="store_true", help="Runs all enumeration checks.")
parser.add_argument("-s", "--service", action="store_true", help="Displays all service executable paths.")
parser.add_argument("-c", "--acl", action="store_true", help="Prints all executable path permissions.")
parser.add_argument("-r", "--reg", action="store_true", help="Enumerate all potentially vulnerable registries.")
parser.add_argument("-p", "--priv", action="store_true", help="Enumerate user permissions.")
parser.add_argument("-d", "--cred", action="store_true", help="Credential extraction.")
parser.add_argument("-t", "--startup", action="store_true", help="Checks registry statup.")
args = parser.parse_args()


def get_services():
    print(f"\n{LIGHT_CYAN}[INFO]{RESET} {LIGHT_PURPLE}Querying Window services...{RESET}")

    paths = []
    quoted = []
    unquoted = []
    missing_paths = []

    cmd = ["cmd", "/c", "sc", "query", "state=all", "type=service"]
    service = subprocess.run(cmd, capture_output=True, text=True, errors="replace")

    if service.returncode != 0:
        print(f"\n    {RED}[ERROR]{RESET} {LIGHT_PURPLE}Ensure you are running with sufficient privileges.{RESET}")
        return paths ,quoted ,unquoted, missing_paths

    svc_names = re.findall(r"SERVICE_NAME:\s*(.+?)\s*$", service.stdout, re.MULTILINE)

    for service_name in svc_names:
        try:
            svc_info = subprocess.check_output(["sc", "qc", service_name.strip()], text=True, errors="replace")
            path_match = re.search(r"BINARY_PATH_NAME\s*:\s*(.+)", svc_info)
            if path_match:
                paths.append(path_match.group(1).strip())
        except subprocess.CalledProcessError:
            continue

    unique_paths = list(dict.fromkeys(paths))

    for path in unique_paths:
        clean_path = path.strip('"')
        if path.startswith('"'):
            quoted.append(path)
        else:
            unquoted.append(path)


        exe_split = clean_path.lower().find('.exe')
        if exe_split != -1:
            file_path = clean_path[:exe_split + 4]
            if not os.path.exists(file_path):
                missing_paths.append(file_path)

    return unique_paths, quoted, unquoted, missing_paths


def acl(paths):
    print(f"\n{LIGHT_CYAN}[INFO]{RESET} {LIGHT_PURPLE}Checking permission on service binaries...{RESET}")
    time.sleep(3)

    for path in paths:
        clean_path = path.strip('"')
        if not os.path.exists(clean_path):
            parts = clean_path.split('.exe')
            if len(parts) > 1:
                clean_path = parts[0] + '.exe'

        print(f"{LIGHT_CYAN}[*] {LIGHT_PURPLE}Target: {clean_path}{RESET}")
        results = subprocess.run(["cmd", "/c", "icacls", clean_path],capture_output=True, text=True, errors="replace")
        print(results.stdout if results.stdout else f"{RED}[!]{RESET} {LIGHT_PURPLE}No output or path not found.{RESET}")


def enum_reg():
    print(f"\n{LIGHT_CYAN}[INFO]{RESET} {LIGHT_PURPLE}Enumerating potential vulnerable registry keys...{RESET}")
    import winreg

    registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", "AlwaysInstallElevated (HKLM)"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", "AlwaysInstallElevated (HKCU)"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", "LSA Protection (RunAsPPL)")
    ]

    for hive, subkey, value_name, description in registry_paths:
        try:
            registry_key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
            value, reg_type = winreg.QueryValueEx(registry_key, value_name)
            winreg.CloseKey(registry_key)

            if value == 1:
                print(f"\n    {RED}[!] Vulnerable:{RESET} {LIGHT_PURPLE}{description}{RESET} is enabled (Value: {value}){RESET}")
            else:
                print(f"    {LIGHT_CYAN}[*]{RESET} {LIGHT_PURPLE} {description} is disabled (Value: {value})")
        except FileNotFoundError:
            print(f"    {RED}[!]{RESET} {LIGHT_PURPLE} {description} was not found.{RESET}")
        except Exception as e:
            print(f"    {RED}[ERROR]{RESET} {LIGHT_PURPLE}Error: {e}{RESET}")


def check_privileges():
    print(f"\n{LIGHT_CYAN}[INFO]{RESET} {LIGHT_PURPLE}Checking privileges...{RESET}")
    result = subprocess.run(["cmd", "/c", "whoami", "/all"], capture_output=True, text=True, errors="replace")

    if "SeImpersonatePrivilege" in result.stdout:
        print(f"\n\n    {RED}[!] Vulnerable:{RESET} {LIGHT_PURPLE} SeImpersonatePrivilege is vulnerable!{RESET}")
    elif "SeBackup" in result.stdout and "SeRestore" in result.stdout:
        print(f"\n\n    {RED}[!] Vulnerable:{RESET} {LIGHT_PURPLE} SeBackup / SeRestore is vulnerable{RESET}")
    else:
        print(result.stdout)


def cred_exfil():
    print(f"\n{LIGHT_CYAN}[INFO]{RESET} Checking if credential exfiltration is possible...{RESET}")

    temp = r"C:\temp"

    if not os.path.exists(temp):
        try:
            os.makedirs(temp)
            print(f"\n    {LIGHT_CYAN}[*]{RESET} {LIGHT_PURPLE}Created directory: {temp}{RESET}")
        except Exception as e:
            print(f"\n    {RED}[ERROR]{RESET} {LIGHT_PURPLE}Error: {e}{RESET}")
            return
    try:
        sys_res = subprocess.run(["cmd", "/c", "reg", "save", r"hklm\system", r"C:\temp\system.hive"], capture_output=True, text=True, errors="replace")
        sam_res = subprocess.run(["cmd", "/c", "reg", "save", r"hklm\sam", r"C:\temp\sam.hive"], capture_output=True, text=True, errors="replace")

        if sys_res.returncode == 0 and sam_res.returncode == 0:
            print(f"\n    {RED}[!]{RESET} {LIGHT_PURPLE}Successfully copied SAM and SYSTEM to C:\\temp.{RESET}")
        else:
            print(f"\n    {RED}[ERROR]{RESET} {LIGHT_PURPLE}Access denied or execution failed. Ensure you are running with administrative privileges.{RESET}")

            if sys_res.stderr.strip():
                print(f"    {RED}[-] SYSTEM Hive Error: {sys_res.stderr.strip()}{RESET}")
            if sam_res.stderr.strip():
                print(f"    {RED}[-] SAM Hive Error: {sam_res.stderr.strip()}{RESET}")
    except Exception as e:
        print(f"\n    {RED}[ERROR]{RESET} {LIGHT_PURPLE}Execution failed with exception: {e}{RESET}")


def enum_startup():
    import winreg

    autorun_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    ]

    print(f"\n{LIGHT_CYAN}[INFO]{RESET} {LIGHT_PURPLE}Enumerating {len(autorun_paths)} Startup and Autorun Registry Keys...{RESET}")

    for hive, subkey, description in autorun_paths:
        try:
            registry_key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
            i = 0
            found_any = False
            while True:
                try:
                    name, value, reg_type = winreg.EnumValue(registry_key, i)
                    print(f"    {LIGHT_CYAN}[*]{RESET} {LIGHT_PURPLE}[{description}] {BOLD}{name}{RESET} -> {value}")
                    found_any = True
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(registry_key)
            if not found_any:
                print(f"    {LIGHT_CYAN}[*]{RESET} {LIGHT_PURPLE}No entries found in {description}.{RESET}")
        except FileNotFoundError:
            print(f"\n    {LIGHT_CYAN}[*]{RESET} {LIGHT_PURPLE}Registry path {description} not found.{RESET}")
        except Exception as e:
            print(f"\n    {RED}[ERROR]{RESET} {LIGHT_PURPLE}Error accessing {description}: {e}{RESET}")

if not any(vars(args).values()):
    parser.print_help()
else:
    paths, quoted, unquoted, missing_paths = get_services()

    if args.service or args.all:
        print(f"\n{LIGHT_CYAN}[INFO]{RESET} {LIGHT_PURPLE}Unquoted Service paths found{RESET} {len(unquoted)}:")
        for p in unquoted:
            print(f"    {p}")

        print(f"\n{LIGHT_CYAN}[INFO]{RESET} {LIGHT_PURPLE}Quoted Service paths found{RESET} {len(quoted)}:")
        for p in quoted:
            print(f"    {p}")

        print(f"\n{RED}[!]{RESET} {LIGHT_PURPLE}Missing Service Binaries found{RESET} {len(missing_paths)}:")
        for p in missing_paths:
            print(f"    {p}")

    if args.acl or args.all:
        if paths:
            acl(paths)
        else:
            print(f"\n{RED}[!]{RESET} {LIGHT_PURPLE}No paths available for ACL inspection.{RESET}")

    if args.reg or args.all:
        enum_reg()

    if args.priv or args.all:
        check_privileges()

    if args.cred or args.all:
        cred_exfil()

    if args.startup or args.all:
        enum_startup()
