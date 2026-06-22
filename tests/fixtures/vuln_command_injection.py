import os
import subprocess


def run_scan(target):
    os.system(f"nmap -sV {target}")


def check_host(host):
    subprocess.run(f"ping -c 1 {host}", shell=True)
