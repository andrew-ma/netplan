# Netplan

NOTE: Only works on Linux!

## Installation
```
pip install -e .
```

## Commands
* To only print the commands and not run them (useful for copy and paste, or dry run), specify `--print-only` option

* To run commands on a Remote Machine (SSH), specify `--destination SSH_DESTINATION` and `--password-file SSH_PASSWORD_FILE` options

* To skip having to type in SSH password, install `sshpass`, and specify `--use-sshpass` option

```
# For Adding VLAN Interfaces
netplan -h


# For Deleting VLAN Interfaces
delete_vlans -h
```

## Examples
```
netplan -m 00:0c:29:31:c3:6f -n test${i} -i 192.168.2.4/30 -g 192.168.2.3 -v 47 -d andrew@localhost -p password.txt  --use-sshpass --print-only
```