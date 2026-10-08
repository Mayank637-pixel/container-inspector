#!/usr/bin/env python3
import sys
import subprocess
import os
def get_pid(container_name):
    command = f"sudo docker inspect -f='{{{{.State.Pid}}}}' {container_name}"
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL)
        pid=result.decode("utf-8").strip()
        if pid=='0' or pid=="":
            return None
        else:
            return pid
    except subprocess.CalledProcessError:
        return None
def pid_namespace(host_pid):
            command= f"sudo nsenter --target {host_pid} -p -m ps -o pid,comm"
            try:
                result = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL)
                pids=result.decode("utf-8").strip()
                return pids
            except subprocess.CalledProcessError:
                return "Failed to get PID namespace"
def get_mount_overlayfs(host_pid):
    path=f"/proc/{host_pid}/mountinfo"
    overlay_data={"upperdir":None,"lowerdir":None,"workdir":None}
    if not os.path.exists(path):
        return None
    try:
        with open(path,"r") as f:
            for line in f:
                if "- overlay overlay" in line:
                    opts = line.split(" - overlay overlay ")[1].strip()
                    for opt in opts.split(","):
                        if opt.startswith("upperdir="):
                            overlay_data["upperdir"] = opt.split("=", 1)[1]
                        elif opt.startswith("lowerdir="):
                            overlay_data["lowerdir"] = opt.split("=", 1)[1]
                        elif opt.startswith("workdir="):
                            overlay_data["workdir"] = opt.split("=", 1)[1]
                            break
    except PermissionError:
        return "Run as root"
    return overlay_data

def network_namespace(host_pid):
    network_info = {"interfaces": [], "listening_ports": []}
    command=f"sudo nsenter --target {host_pid} -n ip -br addr"
    try:
        ip_output = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL).decode().strip()
        network_info["interfaces"] = ip_output.splitlines()
    except subprocess.CalledProcessError:
        network_info["interfaces"] = ["Unable to read interfaces"]
    port_cmd = f"sudo nsenter --target {host_pid} -n ss -tuln"
    try:
        port_output = subprocess.check_output(port_cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
        network_info["listening_ports"] = port_output.splitlines()
    except subprocess.CalledProcessError:
        network_info["listening_ports"] = ["Unable to read ports"]

    return network_info

def get_cgroup_limits(host_pid):
    cgroup_file = f"/proc/{host_pid}/cgroup"
    limits = {
        "cpu_quota": "Unrestricted",
        "pids_max": "Unrestricted",
        "pids_current": "Unknown",
        "cgroup_path": None
    }
    if not os.path.exists(cgroup_file):
        return limits
    try:
        with open(cgroup_file, "r") as f:
            for line in f:
                if line.startswith("0::"):
                    relative_path = line.strip().split("::")[1]
                    limits["cgroup_path"] = f"/sys/fs/cgroup{relative_path}"
                    break
    except Exception:
        return limits

    base = limits["cgroup_path"]
    if not base or not os.path.exists(base):
        return limits
    cpu_file = os.path.join(base, "cpu.max")
    if os.path.exists(cpu_file):
        try:
            val = open(cpu_file).read().strip()
            quota, period = val.split()
            if quota != "max":
                cores = int(quota) / int(period)
                limits["cpu_quota"] = f"{cores:.2f} Core(s) ({quota}/{period} us)"
            else:
                limits["cpu_quota"] = "max (Unrestricted)"
        except Exception:
            pass
    pids_max_file = os.path.join(base, "pids.max")
    if os.path.exists(pids_max_file):
        try:
            val = open(pids_max_file).read().strip()
            limits["pids_max"] = "max (Unrestricted)" if val == "max" else val
        except Exception:
            pass
    pids_cur_file = os.path.join(base, "pids.current")
    if os.path.exists(pids_cur_file):
        try:
            limits["pids_current"] = open(pids_cur_file).read().strip()
        except Exception:
            pass

    return limits


def get_capabilities(host_pid):
    
    status_file = f"/proc/{host_pid}/status"
    cap_info = {
        "hex_mask": "Unknown",
        "decoded_caps": [],
        "high_risk_detected": []
    }
    if not os.path.exists(status_file):
        return cap_info
    try:
        with open(status_file, "r") as f:
            for line in f:
                if line.startswith("CapBnd:"):
                    cap_info["hex_mask"] = line.split()[1].strip()
                    break
    except Exception:
        return cap_info
    if cap_info["hex_mask"] != "Unknown":
        decode_cmd = f"capsh --decode={cap_info['hex_mask']}"
        try:
            output = subprocess.check_output(decode_cmd, shell=True, stderr=subprocess.DEVNULL)
            decoded_str = output.decode("utf-8").strip()
           
            caps = [c.strip() for c in decoded_str.split(",") if c.strip()]
            cap_info["decoded_caps"] = caps

            critical_caps = [
                "cap_sys_admin", "cap_sys_ptrace", "cap_sys_module",
                "cap_sys_rawio", "cap_sys_time", "cap_dac_read_search"
            ]
            for c in caps:
                if c.lower() in critical_caps:
                    cap_info["high_risk_detected"].append(c)

        except Exception:
            cap_info["decoded_caps"] = ["capsh utility not found (raw mask shown)"]

    return cap_info   


def get_mac_profile(host_pid):
    attr_paths = [
        f"/proc/{host_pid}/attr/current",
        f"/proc/{host_pid}/attr/apparmor/current"
    ]
    
    for path in attr_paths:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    profile = f.read().strip()
                    if profile:
                        return profile
            except Exception:
                pass

    return "Unavailable / Unconfined"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: scanner.py <container_name>")
        sys.exit(1)
    container_name = sys.argv[1]
    host_pid = get_pid(container_name)
    if not host_pid:
        print(f"Container {container_name} is running with PID {host_pid}")
        sys.exit(1)
    print(f"\n==================================================")
    print(f"  ContainerScope: Target [{container_name}]")
    print(f"==================================================")
    print(f"[+] HOST PROCESS IDENTIFIER")
    print(f"    └── Real Host PID: {host_pid}")
    print(f"\n[+] INTERNAL PID VIEW (nsenter -p -m ps)")
    internal_ps = pid_namespace(host_pid)
    for line in internal_ps.splitlines():
        print(f"    └── {line}")
    print(f"==================================================\n")    


    print(f"\n[+] MOUNT NAMESPACE & OVERLAYFS (/proc/{host_pid}/mountinfo)")
    overlay = get_mount_overlayfs(host_pid)
    if isinstance(overlay, dict) and overlay.get("upperdir"):
        print(f"    ├── Host Scratchpad (upperdir):")
        print(f"    │   └── {overlay['upperdir']}")
        try:
            written_files = os.listdir(overlay['upperdir'])
            print(f"    └── Files Created/Modified inside Container:")
            if written_files:
                for file_entry in written_files:
                    print(f"        └── {file_entry}")
            else:
                print(f"        └── (None yet - container filesystem is untouched)")
        except Exception as e:
            print(f"    └── Could not list upperdir: {e}")
    else:
        print(f"    └── No OverlayFS root found or {overlay}")

    print(f"==================================================\n")

    print(f"\n[+] NETWORK NAMESPACE (nsenter -n)")
    net_data = network_namespace(host_pid)
    print(f"    ├── Interfaces & Addresses:")
    for iface in net_data["interfaces"]:
        print(f"    │   └── {iface}")
    print(f"    └── Listening Ports:")
    for port in net_data["listening_ports"]:
        print(f"        └── {port}")

    print(f"==================================================\n")

    print(f"\n[+] CGROUPS v2 (Resource Quotas & DoS Defenses)")
    cg = get_cgroup_limits(host_pid)
    print(f"    ├── Hierarchy Path   : {cg['cgroup_path']}")
    print(f"    ├── CPU Allocation   : {cg['cpu_quota']}")
    print(f"    ├── Process Ceiling  : {cg['pids_max']} (pids.max)")
    print(f"    └── Active Processes : {cg['pids_current']} (pids.current)")

    print(f"==================================================\n")

    print(f"\n[+] CAPABILITIES (Privilege Decomposition & Bounding Set)")
    caps = get_capabilities(host_pid)
    print(f"    ├── Raw CapBnd Mask  : 0x{caps['hex_mask']}")
    print(f"    ├── Granted Count    : {len(caps['decoded_caps'])} capabilities")
    
    if caps["high_risk_detected"]:
        print(f"    └── [!] WARNING - High Risk Superpowers Present:")
        for danger in caps["high_risk_detected"]:
            print(f"        └── {danger}")
    else:
        print(f"    └── Security Baseline: Safe default (High-risk capabilities like CAP_SYS_ADMIN dropped)")

    print(f"==================================================\n")
    
    print(f"\n[+] MANDATORY ACCESS CONTROL (MAC / AppArmor)")
    profile = get_mac_profile(host_pid)
    print(f"    └── Active Security Profile : {profile}")
    
    if "unconfined" in profile.lower():
        print(f"    └── [!] WARNING: Container running UNCONFINED (No AppArmor profile)!")
    elif "docker-default" in profile:
        print(f"    └── Enforcing standard Docker profile (blocks sensitive writes and raw mount ops)")
    else:
        print(f"    └── Enforcing custom AppArmor profile")
