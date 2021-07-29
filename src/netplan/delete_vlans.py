import argparse
from netplan.app import (
    wrap_command_with_ssh,
    run_command_pretty_print,
    ssh_destination_argtype,
    password_file_argtype,
)


def get_args():
    parser = argparse.ArgumentParser()

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
    parser.add_argument(
        "--use-sshpass",
        dest="use_sshpass",
        action="store_true",
        help="If selected, then it will attempt to use sshpass (if installed) to skip having to type SSH passwords.",
    )
    parser.set_defaults(print_only=False, use_sshpass=False)

    args = parser.parse_args()

    if args.ssh_destination is not None:
        # require password
        if not args.ssh_password_file:
            parser.error("SSH mode requires password file")

    return (args, parser)


def main():
    args, _ = get_args()
    ssh_destination = args.ssh_destination
    ssh_password_filename = args.ssh_password_file

    command = """vlan_connection_ids=($(nmcli c | awk '{NF-=1} {if ($NF == "vlan") print $(NF-1)}'))
for id in ${vlan_connection_ids[@]}; do nmcli connection delete "${id}"; done"""

    if ssh_destination:
        command = wrap_command_with_ssh(
            command,
            ssh_destination,
            ssh_password_filename,
            use_sshpass=args.use_sshpass,
        )

    run_command_pretty_print(command, print_only=args.print_only)


if __name__ == "__main__":
    main()
