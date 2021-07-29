import sys
import os
import subprocess
import re
import argparse
import logging

log = logging.getLogger(__name__)


def setup_logging():
    LOG_FORMAT = "[%(levelname)s] %(message)s"

    logging.basicConfig(
        level=logging.INFO,
        format=LOG_FORMAT,
        handlers=[logging.StreamHandler()],
    )


def is_valid_MAC_address(mac_address: str):
    mac_address_pattern = re.compile(
        r"[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}"
    )

    match_obj = mac_address_pattern.match(mac_address)
    if match_obj is None:
        return False
    else:
        return True


def mac_address_argtype(value):
    if is_valid_MAC_address(value):
        return value
    else:
        raise argparse.ArgumentTypeError(
            "MAC address must have format: 00:00:00:00:00:00"
        )


def is_valid_IP_address(ip_address: str, *, has_cidr=False):
    # Checks numbers are 1 to 3 digits long
    # and 4 numbers
    # and has period separators
    # and CIDR notation subnet mask "/" 1 to 2 digit number
    ip_pattern_str = r"(\d{1,3})[.](\d{1,3})[.](\d{1,3})[.](\d{1,3})"
    if has_cidr:
        ip_pattern_str += r"[/](\d{1,2})"
    ip_subnet_pattern = re.compile(ip_pattern_str)
    match_obj = ip_subnet_pattern.match(ip_address)
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

        if has_cidr:
            # Last part is the subnet mask value
            if parts[4] > max_subnet_value:
                return False

        return True


def ip_address_cidr_argtype(value):
    if is_valid_IP_address(value, has_cidr=True):
        return value
    else:
        raise argparse.ArgumentTypeError(
            "IP address with CIDR must have format: 192.168.1.1/24"
        )


def ip_address_argtype(value):
    if is_valid_IP_address(value, has_cidr=False):
        return value
    else:
        raise argparse.ArgumentTypeError("IP address must have format: 192.168.1.1")


def vlan_id_argtype(value):
    try:
        value = int(value)
        if value < 0 or value > 4095:
            raise ValueError
        return value
    except ValueError:
        raise argparse.ArgumentTypeError(
            "VLAN ID must be a valid integer in range (0-4095)"
        )


def password_file_argtype(value):
    if not os.path.exists(value):
        raise argparse.ArgumentTypeError(f"Password file '{value}'' does not exist")

    return value


def ssh_destination_argtype(value):
    destination_pattern = re.compile(
        r"(?:(.*)[:][/][/])?(?:(.*)[@])?([^:]+)(?:[:]([\d]+))?"
    )
    m = destination_pattern.match(value)
    uri_form_protocol_part = m.group(1)
    uri_form_port_part = m.group(4)
    invalid = False
    if m is None:
        invalid = True
    elif uri_form_protocol_part and uri_form_protocol_part != "ssh":
        invalid = True
    elif not uri_form_protocol_part and uri_form_port_part:
        # Can't specify :port without ssh:// in front
        invalid = True

    if invalid:
        raise argparse.ArgumentTypeError(
            "SSH Destination must be in format: '[user@]hostname' or 'ssh://[user@]hostname[:port]'"
        )

    return value


def get_args():
    parser = argparse.ArgumentParser()
    network_details_group = parser.add_argument_group("nmcli arguments")
    network_details_group.add_argument(
        "-m",
        "--mac-address",
        type=mac_address_argtype,
        required=True,
        help="MAC address of interface is used to get the Interface Name. Ex: '00:00:00:00:00:00'",
    )
    network_details_group.add_argument(
        "-n", "--connection-name", required=True, help="Name of connection in nmcli"
    )
    network_details_group.add_argument(
        "-i",
        "--ip-address",
        type=ip_address_cidr_argtype,
        required=True,
        help="IPv4 Address with CIDR subnet. Ex: '192.168.1.2/20'",
    )
    network_details_group.add_argument(
        "-g",
        "--gateway",
        type=ip_address_argtype,
        required=True,
        help="Gateway Address. Ex: '192.168.1.1'",
    )
    network_details_group.add_argument(
        "-v", "--vlan-id", type=vlan_id_argtype, required=True, help="VLAN ID (0-4095)"
    )

    ssh_group = parser.add_argument_group("ssh arguments")
    ssh_group.add_argument(
        "-d",
        "--destination",
        dest="ssh_destination",
        type=ssh_destination_argtype,
        help="Formats: '[user@]hostname', 'ssh://[user@]hostname[:port]'. Ex: 'andrew@192.168.1.3', 'ssh://joe@192.168.1.4:22'",
    )
    ssh_group.add_argument(
        "-p",
        "--password-file",
        dest="ssh_password_file",
        type=password_file_argtype,
        help="The password is the first line of the file",
    )

    parser.add_argument(
        "--print-only",
        dest="print_only",
        action="store_true",
        help="If selected, the commands will only be printed and not run.",
    )
    parser.set_defaults(print_only=False)

    args = parser.parse_args()

    if args.ssh_destination is not None:
        # require password
        if not args.ssh_password_file:
            parser.error("SSH mode requires password file")

    return (args, parser)


def create_command(mac_address, connection_name, ip_address, gateway, vlan_id):
    command = f"""mac_address="{mac_address}"
connection_name="{connection_name}"
ip_address="{ip_address}"
gateway="{gateway}"
vlan_id="{vlan_id}"
"""
    command += """interface=$(ip -o link show | grep "\s${mac_address}\s" | grep -v '@' | awk '{print substr($2, 1, length($2)-1)}')
if [[ ! -z "${interface}" ]]; then
    echo "Found interface: '${interface}'"
    sudo nmcli connection delete "${connection_name}" 2>/dev/null
    sudo nmcli connection add type vlan con-name "${connection_name}" dev "${interface}" id "${vlan_id}" ip4 "${ip_address}" gw4 "${gateway}" ipv6.addr-gen-mode eui64 && sudo nmcli connection up "${connection_name}"
    nmcli connection
else
    1>&2 echo "No Interface Found with MAC Address: '${mac_address}'"
fi"""
    return command


def wrap_command_with_ssh(command, ssh_destination, ssh_password_filename):
    ssh_command = f"""cat "{ssh_password_filename}" - << 'EOF' |\n"""
    ssh_command += command
    if command_exists("sshpass"):
        ssh_command += f"""\nEOF\nsshpass -f "{ssh_password_filename}" -- ssh "{ssh_destination}" 'sudo --prompt="" -S -s'"""
    else:
        ssh_command += f"""\nEOF\nssh "{ssh_destination}" 'sudo --prompt="" -S -s'"""
    
    return ssh_command


def command_exists(command):
    check_command = f'command -v "{command}"'
    _, error = run_command(check_command)
    if error:
        return False
    else:
        return True


def run_command(
    command: str, *, return_bytes: bool = False, print_command: bool = False
):
    if print_command:
        print(command)
    result = subprocess.run(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    output_bytes = result.stdout
    error_bytes = result.stderr
    if return_bytes:
        return (output_bytes, error_bytes)
    else:
        return (output_bytes.decode().strip(), error_bytes.decode().strip())


def run_command_pretty_print(
    command: str, *, print_only: bool = False, header_width: int = 70
):
    print(f"{' COMMAND ':=^{header_width}}")
    print(command)

    if print_only:
        return

    print(f"{' RUN ':=^{header_width}}")
    output, error = run_command(command)
    print(f"{' OUTPUT ':=^{header_width}}")
    if output:
        print(output)
    print(f"{' ERROR ':=^{header_width}}")
    if error:
        print(error, file=sys.stderr)


def main():
    setup_logging()
    args, _ = get_args()

    ssh_destination = args.ssh_destination
    ssh_password_filename = args.ssh_password_file
    mac_address = args.mac_address
    connection_name = args.connection_name
    ip_address = args.ip_address
    gateway = args.gateway
    vlan_id = args.vlan_id

    command = create_command(mac_address, connection_name, ip_address, gateway, vlan_id)
    if ssh_destination:
        command = wrap_command_with_ssh(command, ssh_destination, ssh_password_filename)

    run_command_pretty_print(command, print_only=args.print_only)


if __name__ == "__main__":
    main()
