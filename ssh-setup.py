"""
Enables ssh private key authentication for the target server
Generate a new ed25519 private key if the user does not have one
and add the corresponding public key to the target servers 
authorized hosts file if it does not exist
"""
import re
import os
import sys
import subprocess

# local .ssh path
ssh_path = os.path.join(os.path.expanduser('~'), ".ssh")

# private key file
id_ed25519 = os.path.join(ssh_path, "id_ed25519")

# public key file
id_ed25519_pub = os.path.join(ssh_path, "id_ed25519.pub")

# if the private key file does not exist, create it
if not os.path.exists(id_ed25519):

    # if the .ssh path does not exist, create
    if not os.path.exists(ssh_path):
        os.mkdir(ssh_path)

    # Generate new private key with no passphrase
    process = subprocess.Popen(['ssh-keygen ', 
        '-q', '-t', 'ed25519', '-N', "''", '-f', 'id_ed25519'],
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

# if the public key file does not exist, create
if not os.path.exists(id_ed25519_pub):
    process = subprocess.Popen(['ssh-keygen ', 
        '-f', 'id_ed25519', '-y', '>', 'id_ed25519_pub'],
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

# Get the public key
with open(id_ed25519_pub,'r') as file:
    public_key = file.read()

# sh commands to run on the remote server
cmd  = "k='" + public_key + "'; "
cmd += 'for d in "/etc/dropbear" "~/.ssh"; '
cmd += 'do f="$d/authorized_keys"; '
cmd += 'if [ -d "$d" ]; '
cmd += 'then if [ ! -f "$f" ] || grep -vq "$k" "$f"; '
cmd += 'then echo "$k" >> "$f"; fi; fi; done;'
# escape the $ character
cmd = re.sub(r'\$', '\$', cmd)

cmd = ["ssh"] + sys.argv[1:] + [cmd]

# ssh into the remote server and run commands to add our public key
# to it's authorized hosts file
process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
stdout, stderr = process.communicate()

# success statement
print("done")