# Netplan

## Installation
```
pip install -e .
```

## Commands
* To only print the commands and not run them (useful for copy and paste, or dry run), specify `--print-only` option

* To run commands on a Remote Machine (SSH), specify `--destination SSH_DESTINATION` and `--password-file SSH_PASSWORD_FILE` options

```
# For Adding VLAN Interfaces
netplan -h


# For Deleting VLAN Interfaces
delete_vlans -h
```