# Netplan

* Printing the commands (`--print-only`) works on both Windows and Linux
* Running the commands (without `--print-only`) only works on Linux

## Installation
> Windows: substitute python3 with python
```
python3 -m pip install --upgrade .
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
netplan --mac-address 00:0c:29:31:c3:6f --connection-name ABC_123 --ip-address 192.168.2.4/24 --gateway 192.168.2.1 --vlan-id 2 --destination andrew@localhost --password password.txt --use-sshpass --print-only
```
