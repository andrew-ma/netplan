"""This script so far is designed to be run on each individual system
"""
import argparse
from collections import defaultdict
import logging
import os
import re
import sys
import subprocess
from subprocess import check_output, Popen, PIPE
import shlex
import pandas as pd

log = logging.getLogger(__name__)


def setup_logging():
    LOG_FORMAT = "[%(levelname)s] %(message)s"

    logging.basicConfig(
        level=logging.INFO,
        format=LOG_FORMAT,
        handlers=[logging.StreamHandler()],
    )


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("CSV_FILE")
    parser.add_argument("MAC_ADDRESS")
    args = parser.parse_args()
    return args


class NoSpaceStringConverter(dict):
    def __contains__(self, item):
        return True

    def __getitem__(self, item):
        # Remove Spaces for values in these columns
        return lambda val: str(val).replace(" ", "")

    def get(self, default=None):
        return str


def create_Interface_Name(town, building):
    return "{}_{}".format(town[0:3].upper(), building)


def get_Connection_Name_to_WAN_Address_dict(dataframe):
    # Create a new dataframe with
    connection_Name_to_WAN_Address_df = dataframe.apply(
        lambda row: (
            create_Interface_Name(row["Town"], row["Building"]),
            row["WAN Address"],
        ),
        axis=1,
        result_type="expand",
    )

    connection_Name_to_WAN_Address_df.rename(
        columns={0: "Interface Name", 1: "WAN Address"}, inplace=True
    )

    # NOTE: this could be a cause of error if a (Town, Building) combination has multiple WAN Addresses associated with it
    # Convert the dataframe to a dictionary {"Interface Name": "WAN Address"}

    connection_Name_to_WAN_Address_dict = connection_Name_to_WAN_Address_df.set_index(
        "Interface Name"
    ).to_dict()["WAN Address"]

    return connection_Name_to_WAN_Address_dict

    ### Make values type 'set' if a (Town, Building) combination has multiple WAN Addresses associated with it
    # connection_Name_to_WAN_Address_set_dict = defaultdict(set)

    # def add_WAN_Address_to_set(row):
    #     connection_Name_to_WAN_Address_set_dict[row["Interface Name"]].add(
    #         row["WAN Address"]
    #     )

    # connection_Name_to_WAN_Address_df.apply(add_WAN_Address_to_set, axis=1)

    # return dict(connection_Name_to_WAN_Address_set_dict)


def get_Connection_Name_to_WAN_Info_dict(dataframe):
    # Create a new dataframe with
    connection_Name_to_WAN_Info_df = dataframe.apply(
        lambda row: pd.Series(
            (
                create_Interface_Name(row["Town"], row["Building"]),
                row["WAN Address"],
                row["WAN GW"],
                row["WAN Vlan"],
            )
        ),
        axis=1,
        result_type="expand",
    )

    connection_Name_to_WAN_Info_df.rename(
        columns={0: "Interface Name", 1: "WAN Address", 2: "WAN GW", 3: "WAN Vlan"},
        inplace=True,
    )
    # NOTE: this could be a cause of error if a (Town, Building) combination has multiple WAN Addresses associated with it
    # Convert the dataframe to a dictionary {"Interface Name": "WAN Address"}

    # connection_Name_to_WAN_Address_dict = connection_Name_to_WAN_Address_df.set_index(
    #     "Interface Name"
    # ).to_dict()

    # Use 'Interface Name' as the unique index, so remove duplicates

    connection_Name_to_WAN_Info_df.drop_duplicates(
        subset=("Interface Name"), inplace=True
    )

    connection_Name_to_WAN_Info_dict = connection_Name_to_WAN_Info_df.set_index(
        "Interface Name"
    ).to_dict("index")

    return connection_Name_to_WAN_Info_dict


def is_valid_WAN_address(WAN_address: str):
    # Checks numbers are 1 to 3 digits long
    # and 4 numbers
    # and has period separators
    # and CIDR notation subnet mask "/" 1 to 2 digit number
    ip_subnet_pattern = re.compile(
        r"(\d{1,3})[.](\d{1,3})[.](\d{1,3})[.](\d{1,3})[/](\d{1,2})"
    )
    match_obj = ip_subnet_pattern.match(WAN_address)
    if match_obj is None:
        return False
    else:
        # Check that the numbers don't exceed normal values
        max_ip_value = 255
        max_subnet_value = 32

        parts = [int(v) for v in match_obj.groups()]
        # IP parts are first 4 parts
        for ip_part in parts[0:4]:
            if ip_part > max_ip_value:
                return False

        # Last part is the subnet mask value
        if parts[4] > max_subnet_value:
            return False

        return True


def parse_csv_file(filename_or_buffer):
    # Only keep rows that have non-empty NET Address column
    # When reading in csv file into Pandas Dataframe, strip all the spaces, and get back a string
    if isinstance(filename_or_buffer, str):
        if not os.path.exists(filename_or_buffer):
            raise Exception(
                "CSV file '{filename_or_buffer}' does not exist".format(
                    filename_or_buffer
                )
            )

    df = pd.read_csv(
        filename_or_buffer, converters=NoSpaceStringConverter(), encoding="latin-1"
    )

    # Drop csv rows that have empty or invalid ('----') "WAN Address" column values
    df = df[(df["WAN Address"] != "") & (df["WAN Address"].apply(is_valid_WAN_address))]

    # Drop csv rows that have empty "Town" column values
    df = df[df["Town"] != ""]

    # Drop csv rows that have "ALL" for "Town" column
    df = df[df["Town"] != "ALL"]

    # Ensure that there are no rows with invalid "WAN GW" and "WAN Vlan" values
    assert not (df["WAN GW"] == "").any(), "Empty 'WAN GW' value"
    assert not (df["WAN Vlan"] == "").any(), "Empty 'WAN Vlan' value"

    return df


def run_pipe_command(command: str):
    """[summary]

    Parameters
    ----------
    command_str : str
        Command that will be run (can use pipes normally with '|' separator)

    Returns
    -------
    Tuple of (stdout bytes, stderr bytes)
        [description]
    """
    split_command = (shlex.split(pipe_section) for pipe_section in command.split("|"))
    first_command_part = next(split_command)
    cur_process = Popen(first_command_part, stdout=PIPE)

    for command_part in split_command:
        last_process = cur_process
        cur_process = Popen(command_part, stdin=last_process.stdout, stdout=PIPE)
        last_process.stdout.close()

    stdout, stderr = cur_process.communicate()
    return (stdout, stderr)


def main():
    setup_logging()
    args = get_args()

    df = parse_csv_file(args.CSV_FILE)

    connection_Name_to_WAN_Address_dict = get_Connection_Name_to_WAN_Info_dict(df)

    # TODO: Find the interface name
    # MAC address is in colon format
    mac_address = args.MAC_ADDRESS  # 00:0c:29:31:c3:65

    # if mac address is listed as part of an interface, then
    # it will print out the interface name
    # otherwise it will print out nothing
    # interface_name_from_mac_address_command_format = r"ip -o link show | grep '\s{mac_address}\s' | awk '{{print substr($2, 1, length($2)-1)}}'"
    # interface_name_from_mac_address_command = interface_name_from_mac_address_command_format.format(mac_address=args.MAC_ADDRESS)
    # print(interface_name_from_mac_address_command)

    # run_command(interface_name_from_mac_address_command)

    # ip -o link show | grep '\s{mac_address}\s' | awk '{{print substr($2, 1, length($2)-1)}}'
    my_command = r"ip -o link show | grep '\s{mac_address}\s' | grep -v '@' | awk '{{print substr($2, 1, length($2)-1)}}'".format(
        mac_address=args.MAC_ADDRESS
    )
    output, _ = run_pipe_command(my_command)
    interface = output.decode().strip()
    if interface == "":
        log.error(
            "No interface with MAC address {mac_address} was found.".format(
                mac_address=args.MAC_ADDRESS
            )
        )
        sys.exit(1)
    else:
        log.info(
            "Found interface with MAC address {mac_address}:  {interface}".format(
                mac_address=args.MAC_ADDRESS, interface=interface
            )
        )

    # Form the nmcli commands that will be run on each device
    # nmcli_command_format = "nmcli connection add con-name {connection_name} ifname {interface} type ethernet ip4 {ip_address} 802-3-ethernet.mac-address {mac_address}"
    # TODO: be sure to add DNS server settings that show up in /etc/resolv.conf like nameserver {dns server} and search localdomain

    # diff /etc/sysconfig/network-scripts/ifcfg-BAR_AS308 /etc/sysconfig/network-scripts/ifcfg-ens160 4,7c4

    # nmcli_add_connection_command_format = "nmcli connection add type vlan con-name {connection_name} ifname {interface} ip4 {ip_address} gw4 {gateway} ipv6.addr-gen-mode eui64"
    nmcli_add_connection_command_format = (
        "nmcli connection add type vlan con-name {connection_name}"
        " dev {interface} id {vlan} ip4 {ip_address} gw4 {gateway} ipv6.addr-gen-mode eui64"
    )
    nmcli_add_dns_command_format = (
        'nmcli connection mod {connection_name} ipv4.dns "8.8.8.8 8.8.4.4"'
    )
    nmcli_use_connection_command_format = "nmcli connection up {connection_name}"

    connection_name, WAN_info_dict = list(connection_Name_to_WAN_Address_dict.items())[
        0
    ]

    WAN_address = WAN_info_dict["WAN Address"]
    WAN_gateway = WAN_info_dict["WAN GW"]
    WAN_vlan = WAN_info_dict["WAN Vlan"]

    nmcli_add_connection_command = nmcli_add_connection_command_format.format(
        connection_name=connection_name,
        interface=interface,
        ip_address=WAN_address,
        gateway=WAN_gateway,
        vlan=WAN_vlan,
    )
    nmcli_add_dns_command = nmcli_add_dns_command_format.format(
        connection_name=connection_name
    )
    nmcli_use_connection_command = nmcli_use_connection_command_format.format(
        connection_name=connection_name
    )

    print(
        "nmcli connection delete {connection_name}".format(
            connection_name=connection_name
        )
    )
    print(nmcli_add_connection_command)
    print(nmcli_add_dns_command)
    print(nmcli_use_connection_command)

    # for connection_name, WAN_address in connection_Name_to_WAN_Address_dict.items():
    #     # Need to run another command for each system, to get the 'interface' name on that system
    #     # because interface='ens160' is not constant
    #     # Instead detect the interface name based on the "Mac Address" that we read from ESXI

    #     nmcli_add_connection_command = nmcli_add_connection_command_format.format(
    #         connection_name=connection_name, interface=interface, ip_address=WAN_address
    #     )

    #     print(nmcli_add_connection_command)

    #     nmcli_use_connection_command = nmcli_use_connection_command_format.format(
    #         connection_name=connection_name
    #     )

    #     print(nmcli_use_connection_command)


if __name__ == "__main__":
    main()
