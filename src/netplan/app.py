"""This script so far is designed to be run on each individual system

diff /etc/sysconfig/network-scripts/ifcfg-BAR_AS308 /etc/sysconfig/network-scripts/ifcfg-ens160
"""
import argparse
from collections import defaultdict
import logging
import os
import re
import sys
import shlex
from subprocess import Popen, PIPE
import pandas as pd


log = logging.getLogger(__name__)


def setup_logging():
    LOG_FORMAT = "[%(levelname)s] %(message)s"

    logging.basicConfig(
        level=logging.INFO,
        format=LOG_FORMAT,
        handlers=[logging.StreamHandler()],
    )


def mac_address_argtype(value):
    if is_valid_MAC_address(value):
        return value
    else:
        raise argparse.ArgumentTypeError(
            "MAC address must have format: 00:00:00:00:00:00"
        )


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("MAC_ADDRESS", type=mac_address_argtype)

    parser.add_argument("CONNECTION_NAME")

    parser.add_argument("--print-only", dest="print_only", action="store_true")
    parser.set_defaults(print_only=False)

    subparsers = parser.add_subparsers()
    subparsers.required = True
    subparsers.dest = "INPUT_TYPE"

    csv_parser = subparsers.add_parser("csv")
    csv_parser.add_argument("CSV_FILE")

    manual_parser = subparsers.add_parser("manual")
    manual_parser.add_argument("WAN_ADDRESS")
    manual_parser.add_argument("WAN_GATEWAY")
    manual_parser.add_argument("WAN_VLAN")

    args = parser.parse_args()
    return (args, parser)


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


# def get_Connection_Name_to_WAN_Address_dict(dataframe):
#     # Create a new dataframe with
#     connection_Name_to_WAN_Address_df = dataframe.apply(
#         lambda row: (
#             create_Interface_Name(row["Town"], row["Building"]),
#             row["WAN Address"],
#         ),
#         axis=1,
#         result_type="expand",
#     )

#     connection_Name_to_WAN_Address_df.rename(
#         columns={0: "Interface Name", 1: "WAN Address"}, inplace=True
#     )

#     # NOTE: this could be a cause of error if a (Town, Building) combination has multiple WAN Addresses associated with it
#     # Convert the dataframe to a dictionary {"Interface Name": "WAN Address"}

#     connection_Name_to_WAN_Address_dict = connection_Name_to_WAN_Address_df.set_index(
#         "Interface Name"
#     ).to_dict()["WAN Address"]

#     return connection_Name_to_WAN_Address_dict

#     ### Make values type 'set' if a (Town, Building) combination has multiple WAN Addresses associated with it
#     # connection_Name_to_WAN_Address_set_dict = defaultdict(set)

#     # def add_WAN_Address_to_set(row):
#     #     connection_Name_to_WAN_Address_set_dict[row["Interface Name"]].add(
#     #         row["WAN Address"]
#     #     )

#     # connection_Name_to_WAN_Address_df.apply(add_WAN_Address_to_set, axis=1)

#     # return dict(connection_Name_to_WAN_Address_set_dict)


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

    # Use 'Interface Name' as the unique index, so remove duplicates, and this keeps the first entry
    # NOTE: this assumes that each (building, town) combination has the same WAN address for all

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


def is_valid_MAC_address(mac_address: str):
    mac_address_pattern = re.compile(
        r"[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}"
    )

    match_obj = mac_address_pattern.match(mac_address)
    if match_obj is None:
        return False
    else:
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


def run_pipe_command(command: str, *, return_bytes=False):
    """[summary]

    Parameters
    ----------
    command_str : str
        Command that will be run (can use pipes normally with '|' separator)

    Returns
    -------
    Tuple of (stdout, stderr)
        [description]
    """
    print(command)

    pipe_commands = []

    split_command = shlex.split(command)
    start_idx = 0
    try:
        while True:
            found_idx = split_command.index("|", start_idx)
            pipe_commands.append(split_command[start_idx:found_idx])
            start_idx = found_idx + 1
    except ValueError:
        # Last chunk get all the way to end
        pipe_commands.append(split_command[start_idx:])

    pipe_commands_iter = iter(pipe_commands)
    first_pipe_command = next(pipe_commands_iter)
    cur_process = Popen(first_pipe_command, stdout=PIPE, stderr=PIPE)

    for pipe_command in pipe_commands_iter:
        last_process = cur_process
        cur_process = Popen(
            pipe_command, stdin=last_process.stdout, stdout=PIPE, stderr=PIPE
        )
        last_process.stdout.close()
        last_process.stderr.close()

    stdout, stderr = cur_process.communicate()
    cur_process.stdout.close()
    cur_process.stderr.close()

    if return_bytes:
        return (stdout, stderr)
    else:
        return (stdout.decode().strip(), stderr.decode().strip())


def delete_all_vlans(*, print_only=False):
    get_vlan_nmcli_ids_command = (
        "nmcli connection | awk '{if ($3 == \"vlan\") print $2 }'"
    )

    if print_only:
        print(get_vlan_nmcli_ids_command)
    else:
        output, error = run_pipe_command(get_vlan_nmcli_ids_command)

        if output:
            vlan_nmcli_ids = output.split("\n")
            for connection_id in vlan_nmcli_ids:
                run_pipe_command(
                    "nmcli connection delete {connection_id}".format(
                        connection_id=connection_id
                    )
                )


def get_interface_using_mac_address(mac_address, *, print_only=False):
    get_interface_using_mac_address_command = r"ip -o link show | grep '\s{mac_address}\s' | grep -v '@' | awk '{{print substr($2, 1, length($2)-1)}}'".format(
        mac_address=mac_address
    )
    if print_only:
        print(get_interface_using_mac_address_command)
    else:
        output, error = run_pipe_command(get_interface_using_mac_address_command)

        interface = output
        if interface == "":
            return None
        else:
            return interface


def delete_nmcli_connection(connection_name, *, print_only=False):
    nmcli_delete_connection_command = (
        "nmcli connection delete {connection_name}".format(
            connection_name=connection_name
        )
    )
    if print_only:
        print(nmcli_delete_connection_command)
    else:
        output, error = run_pipe_command(nmcli_delete_connection_command)
        if output:
            log.info(output)
        if error:
            log.error(error)


def add_nmcli_vlan_connection(
    connection_name, interface, ip_address, gateway, vlan_id, *, print_only=False
):
    # Form the nmcli commands that will be run on each device
    nmcli_add_connection_command_format = "nmcli connection add type vlan con-name {connection_name} dev {interface} id {vlan_id} ip4 {ip_address} gw4 {gateway} ipv6.addr-gen-mode eui64"

    nmcli_add_connection_command = nmcli_add_connection_command_format.format(
        connection_name=connection_name,
        interface=interface,
        ip_address=ip_address,
        vlan_id=vlan_id,
        gateway=gateway,
    )

    if print_only:
        print(nmcli_add_connection_command)
    else:
        output, error = run_pipe_command(nmcli_add_connection_command)
        if output:
            log.info(output)
        if error:
            log.error(error)


def set_nmcli_connection_dns(
    connection_name, dns_str_or_list=("8.8.8.8", "8.8.4.4"), *, print_only=False
):
    if isinstance(dns_str_or_list, str):
        dns_str = dns_str_or_list
    else:
        dns_str = " ".join(dns_str_or_list)

    nmcli_set_dns_command_format = (
        'nmcli connection mod {connection_name} ipv4.dns "{dns}"'
    )
    nmcli_set_dns_command = nmcli_set_dns_command_format.format(
        connection_name=connection_name, dns=dns_str
    )

    if print_only:
        print(nmcli_set_dns_command)
    else:
        output, error = run_pipe_command(nmcli_set_dns_command)
        if output:
            log.info(output)
        if error:
            log.error(error)


def use_nmcli_connection(connection_name, *, print_only=False):
    nmcli_use_connection_command_format = "nmcli connection up {connection_name}"
    nmcli_use_connection_command = nmcli_use_connection_command_format.format(
        connection_name=connection_name
    )

    if print_only:
        print(nmcli_use_connection_command)
    else:
        output, error = run_pipe_command(nmcli_use_connection_command)
        if output:
            log.info(output)
        if error:
            log.error(error)


def main():
    setup_logging()
    args, parser = get_args()

    connection_name = args.CONNECTION_NAME
    # MAC address is in colon format
    # TODO: validate colon format
    mac_address = args.MAC_ADDRESS  # 00:0c:29:31:c3:65

    if args.INPUT_TYPE == "csv":

        df = parse_csv_file(args.CSV_FILE)
        connection_name_to_WAN_info_dict = get_Connection_Name_to_WAN_Info_dict(df)
    elif args.INPUT_TYPE == "manual":
        wan_address = args.WAN_ADDRESS
        wan_gateway = args.WAN_GATEWAY
        wan_vlan = args.WAN_VLAN
        connection_name_to_WAN_info_dict = {
            connection_name: {
                "WAN Address": wan_address,
                "WAN GW": wan_gateway,
                "WAN Vlan": wan_vlan,
            }
        }

    if connection_name not in connection_name_to_WAN_info_dict:
        parser.error(
            "Connection Name {} not found in: {}".format(
                connection_name, repr(list(connection_name_to_WAN_info_dict.keys()))
            )
        )

    interface = get_interface_using_mac_address(
        args.MAC_ADDRESS, print_only=args.print_only
    )
    if args.print_only:
        interface = "INTERFACE_PLACEHOLDER"
    else:
        if interface is None:
            log.error(
                "No interface with MAC address '{mac_address}' was found.".format(
                    mac_address=args.MAC_ADDRESS
                )
            )
            sys.exit(1)
        else:
            log.info(
                "Found interface with MAC address '{mac_address}': '{interface}'".format(
                    mac_address=args.MAC_ADDRESS, interface=interface
                )
            )

    delete_nmcli_connection(connection_name, print_only=args.print_only)

    WAN_info_dict = connection_name_to_WAN_info_dict[connection_name]
    add_nmcli_vlan_connection(
        connection_name,
        interface,
        WAN_info_dict["WAN Address"],
        WAN_info_dict["WAN GW"],
        WAN_info_dict["WAN Vlan"],
        print_only=args.print_only,
    )

    use_nmcli_connection(connection_name, print_only=args.print_only)


if __name__ == "__main__":
    main()
