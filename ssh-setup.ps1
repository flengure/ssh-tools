<#
Enables ssh private key authentication for the target server
Generate a new ed25519 private key if the user does not have one
and add the corresponding public key to the target servers 
authorized hosts file if it does not exist
#>

# check if ssh client is available
if (-not (Get-Command "ssh" -ErrorAction SilentlyContinue))
{
    if ($IsWindows) 
    {
        Add-WindowsCapability -Online -Name OpenSSH.Client*
        if (-not (Get-Command "ssh" -ErrorAction SilentlyContinue))
        {
            Write-Out "ssh not found\nAn aatempt to install it failed\nPlease install OpenSSH client" 
        }
    } else {
        Write-Out "ssh not found\nPlease install OpenSSH client"
        return
    }
}

# local .ssh path
$ssh_path = Join-Path -Path $HOME -ChildPath ".ssh"

# private key file
$id_ed25519 = Join-Path -Path $ssh_path -ChildPath "id_ed25519"

# public key file
$id_ed25519_pub = Join-Path -Path $ssh_path -ChildPath "id_ed25519.pub"

# if the private key file does not exist, create it
if (-not (Test-Path -Path $id_ed25519 -PathType Leaf)) {

    # if the .ssh path does not exist, create
    if (-not (Test-Path -Path $ssh_path -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $ssh_path
    }

    # Generate new private key with no passphrase
    &ssh-keygen -q -t ed25519 -N '""' -f $id_ed25519
}

# if the public key file does not exist, create
if (-not (Test-Path -Path $id_ed25519_pub -PathType Leaf)) {
    &ssh-keygen -f $id_ed25519 -y > $id_ed25519_pub
}

if (-not ($args)) 
{ 
    Write-Output  "No arguments were passed. Specify like ssh ..."
    exit
}

# Get the public key
$public_key = Get-Content -Path $id_ed25519_pub

# sh commands to run on the remote server
$cmd  = "k='{0}'; "
$cmd += 'for d in "/etc/dropbear" "~/.ssh"; '
$cmd += 'do f="$d/authorized_keys"; '
$cmd += 'if [ -d "$d" ]; '
$cmd += 'then if [ ! -f "$f" ] || grep -vq "$k" "$f"; '
$cmd += 'then echo "$k" >> "$f"; fi; fi; done;'
# insert the public key
$cmd  = $cmd -f $public_key
# escape the $ character
$cmd  = $cmd -replace "\$", "\$"

# ssh into the remote server and run commands to add our public key
# to it's authorized hosts file
&ssh @args $cmd

# success statement
Write-Output "done"