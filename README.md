# Netplan

## Installation
```
pip install -e .
```

## Commands
```
# For Help and Documentation
netplan -h


# For supplying details with CSV
netplan MAC_ADDRESS CONNECTION_NAME csv CSV_FILE


# For specifying single connection details
netplan MAC_ADDRESS CONNECTION_NAME manual WAN_ADDRESS WAN_GATEWAY WAN_VLAN


# To only print commands and not run them
netplan --print-only ...


# Delete all VLANs configured with nmcli
delete_vlans
```