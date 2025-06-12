#!/usr/bin/env python3
import os
import sys
import stat
import subprocess

def main():
    if len(sys.argv) < 3:
        print("Usage: install_conf.py <mydns_executable_path> <config_file_path>")
        sys.exit(1)

    mydns_exe = sys.argv[1]
    conf_file = sys.argv[2]
    conf_dir = os.path.dirname(conf_file)

    if not os.path.exists(mydns_exe):
        print(f"Error: mydns executable not found at {mydns_exe}")
        sys.exit(1)

    if os.path.exists(conf_file):
        print(f"Configuration file {conf_file} already exists. Skipping creation.")
        sys.exit(0)

    print(f"Creating default configuration file at {conf_file}...")
    try:
        if not os.path.exists(conf_dir):
            os.makedirs(conf_dir, exist_ok=True)
            print(f"Created directory {conf_dir}")

        with open(conf_file, 'w') as f:
            # Capture stdout of mydns --dump-config
            result = subprocess.run([mydns_exe, '--dump-config'], stdout=f, check=True, text=True)

        # Set permissions to 0600
        os.chmod(conf_file, stat.S_IRUSR | stat.S_IWUSR)
        print(f"Successfully created {conf_file} with permissions 0600.")

    except subprocess.CalledProcessError as e:
        print(f"Error running {mydns_exe} --dump-config: {e}")
        # Clean up partially created file if error occurred
        if os.path.exists(conf_file):
            os.remove(conf_file)
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        if os.path.exists(conf_file):
            os.remove(conf_file)
        sys.exit(1)

if __name__ == '__main__':
    main()
