#!/usr/bin/env python3

import os
import time
import subprocess
from pathlib import Path
import signal

print("building...")
subprocess.run("cargo build --release", shell=True, check=True)
print("built")

project_info = subprocess.run("cargo metadata --format-version 1 --no-deps | jq -r '.workspace_root'", shell=True, capture_output=True)
PROJECT_DIR = str(project_info.stdout.decode("utf-8").rstrip())
TORTURE_PATH = PROJECT_DIR + "/target/release/torture"
SWARM_DIR= PROJECT_DIR + "/torture/swarm"

FLAG_LIMIT = 3
MAX_DISK = 80
MAX_MEMORY = 60
COMMAND = TORTURE_PATH + " swarm --max-disk " + str(MAX_DISK) + " --max-memory " + str(MAX_MEMORY) + " --workdir " + SWARM_DIR +  " -f " + str(FLAG_LIMIT)
INACTIVITY_LIMIT_MINUTES = 3
INACTIVITY_LIMIT = INACTIVITY_LIMIT_MINUTES * 60
CHECK_INTERVAL = 20 # 20 secs

def get_last_modification(folder_path):
    try:
        mod_time = os.path.getmtime(folder_path)
        return mod_time
    except OSError as e:
        print(f"Error accessing the folder: {e}")
        exit(1)


def start_torture():
    print("Starting torture...")
    return subprocess.Popen(COMMAND, shell=True, preexec_fn=os.setsid)

def kill_process(name):
    try:
        # Use 'ps' command to get the list of running processes
        process_list = subprocess.check_output(['ps', '-eo', 'pid,comm'], text=True)
        # skip the header
        for line in process_list.splitlines()[1:]:
            parts = line.split(maxsplit=2)
            if len(parts) != 2:
                continue

            pid, command = parts
            if name and name in command:
                os.kill(int(pid), signal.SIGKILL)
                return True
    except subprocess.CalledProcessError:
        print("Failed to retrieve process list.")

    return False

def kill_processes(proc):
    if proc.poll() is not None:
        print("Process has already terminated with return code:")
        return True
    else:
        print("Killing torture...")
        gid=proc.pid
        os.killpg(os.getpgid(gid), signal.SIGKILL)
        print("Done")

    print("Kill every child process...")

    # TODO: add a mechanism to attempt killing things for at most
    # an arbitrary amount of time, after it stop trying doing it.
    for process_name in ["torture", "fusermount3", "exe"]:
        while kill_process(process_name):
            time.sleep(5)
    print("Done")

def main():
    #cnt = 0
    running = False

    while True:
        if not running:
            # TODO: redirect each torture execution to a separate file.
            #cnt +=1
            #torture_out = open("torture_out_" + str(cnt), "a")
            #proc = start_torture(torture_out)
            print("Running torture...")
            proc = start_torture()
            print("Done")
            running = True

        time.sleep(CHECK_INTERVAL)

        if proc.poll() is not None:
            kill_processes(proc)
            print("Process stopped. Restarting...")
            running = False
            continue

        # Check directory activity
        last_mod = get_last_modification(SWARM_DIR)
        if time.time() - last_mod > INACTIVITY_LIMIT:
            print("No activity for " + str(INACTIVITY_LIMIT_MINUTES) + " minutes. Restarting ...")
            kill_processes(proc)
            running = False

if __name__ == "__main__":
    main()
