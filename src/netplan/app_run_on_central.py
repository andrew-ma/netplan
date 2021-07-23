"""This script so far is designed to be run on the management system
not on each individual system

That will read the 

It takes in the Excel file 'ThreatVLANs' sheet exported to CSV file

And it forms the commands that will be run 
"""
import argparse
import logging
import os
import sys
import re
from collections import defaultdict
import pandas as pd


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
    args = parser.parse_args()
    return args


class NoSpaceStringConverter(dict):
    def __contains__(self, item):
        return True

    def __getitem__(self, item):
        if item == "FieldValue":
            # for FieldValue, convert to lowercase as well
            return lambda val: str(val).lower().replace(" ", "")

        # Return function that converts value to a string, and then removes all the spaces
        return lambda val: str(val).replace(" ", "")

    def get(self, default=None):
        return str


def create_Interface_Name(town, building):
    return f"{town[0:3].upper()}_{building}"


def get_Interface_Name_to_WAN_Address_dict(dataframe):
    # Create a new dataframe with
    interface_Name_to_WAN_Address_df = dataframe.apply(
        lambda row: (
            create_Interface_Name(row["Town"], row["Building"]),
            row["WAN Address"],
        ),
        axis=1,
        result_type="expand",
    )

    interface_Name_to_WAN_Address_df.rename(
        columns={0: "Interface Name", 1: "WAN Address"}, inplace=True
    )

    # NOTE: this could be a cause of error if a (Town, Building) combination has multiple WAN Addresses associated with it
    # Convert the dataframe to a dictionary {"Interface Name": "WAN Address"}

    interface_Name_to_WAN_Address_dict = interface_Name_to_WAN_Address_df.set_index(
        "Interface Name"
    ).to_dict()["WAN Address"]

    return interface_Name_to_WAN_Address_dict

    ### Make values type 'set' if a (Town, Building) combination has multiple WAN Addresses associated with it
    # interface_Name_to_WAN_Address_list_dict = defaultdict(set)

    # def add_WAN_Address_to_dict(row):
    #     interface_Name_to_WAN_Address_list_dict[row["Interface Name"]].add(
    #         row["WAN Address"]
    #     )

    # interface_Name_to_WAN_Address_df.apply(add_WAN_Address_to_dict, axis=1)

    # return dict(interface_Name_to_WAN_Address_list_dict)


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
            raise Exception(f"CSV file '{filename_or_buffer}' does not exist")

    df = pd.read_csv(filename_or_buffer, converters=NoSpaceStringConverter(), encoding="latin-1")

    # Drop csv rows that have empty or invalid ('----') "WAN Address" column values
    df = df[(df["WAN Address"] != "") & (df["WAN Address"].apply(is_valid_WAN_address))]

    # Drop csv rows that have empty "Town" column values
    df = df[df["Town"] != ""]

    # Temporarily drop csv rows that have "ALL" for "Town" column
    df = df[df["Town"] != "ALL"]

    return df


def create_socket(socket_path: str, host: str, user: str = None, password: str = None):
    if os.path.exists(socket_path):
        raise Exception(f"Socket already exists at {socket_path}")

    optional_user_string = user + "@" if user is not None else ""
    # NOTE: this uses sshpass which allows the password to be a cli arg, but this might not be ideal for security
    # sshpass -e option uses Password set in Environment Variable "SSHPASS"
    create_socket_command = f"sshpass -e ssh -N -f -oStrictHostKeyChecking=no -M -S {socket_path} {optional_user_string}{host}"
    # TODO:  Run the create_socket_command
    print(create_socket_command)
    return socket_path


def kill_socket():
    """Finds the process that created the Master Socket (-M)
    and kills it
    """
    # TODO:Run find_master_socket_pid_command, and get the output and save as process id
    kill_master_socket_pid_command = (
        "ps -ef | grep -v grep | grep -E 'sshpass.+-M' | awk '{print $2}' | xargs kill"
    )
    print(kill_master_socket_pid_command)



def form_ssh_command(
    command: str, socket_path: str = None
):
    if socket_path is not None:
        if not os.path.exists(socket_path):
            raise Exception(f"Socket does not exist at {socket_path}")

        optional_socket_string = "-S {socket_path}"
    else:
        optional_socket_string = ""


    # TODO:Run the ssh_command_format
    ssh_command_format = f"ssh {optional_socket_string} USER_HOST_PLACEHOLDER {command}"


def main():
    setup_logging()
    args = get_args()

    df = parse_csv_file(args.CSV_FILE)

    interface_Name_to_WAN_Address_dict = get_Interface_Name_to_WAN_Address_dict(df)

    print(interface_Name_to_WAN_Address_dict)

    # Form the nmcli commands that will be run on each device
    # nmcli_command_format = "nmcli connection add con-name {connection_name} ifname {interface} type ethernet ip4 {ip_address} 802-3-ethernet.mac-address {mac_address}"
    # TODO: be sure to add DNS server settings that show up in /etc/resolv.conf like nameserver {dns server} and search localdomain
    nmcli_add_connection_command_format = "nmcli connection add con-name {connection_name} ifname {interface} type ethernet ip4 {ip_address}"
    nmcli_use_connection_command_format = "nmcli connection up {connection_name}"

    for connection_name, WAN_address in interface_Name_to_WAN_Address_dict.items():
        # Need to run another command for each system, to get the 'interface' name on that system
        # because interface='ens160' is not constant
        # Instead detect the interface name based on the "Mac Address" that we read from ESXI

        nmcli_add_connection_command = nmcli_add_connection_command_format.format(
            connection_name=connection_name, interface="ens160", ip_address=WAN_address
        )

        print(nmcli_add_connection_command)
        
        nmcli_use_connection_command = nmcli_use_connection_command_format.format(
            connection_name=connection_name
        )
        
        print(nmcli_use_connection_command)


if __name__ == "__main__":
    main()
