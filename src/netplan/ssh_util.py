# import os


# def create_socket(socket_path: str, host: str, user: str = None, password: str = None):
#     if os.path.exists(socket_path):
#         raise Exception(f"Socket already exists at {socket_path}")

#     optional_user_string = user + "@" if user is not None else ""
#     # NOTE: this uses sshpass which allows the password to be a cli arg, but this might not be ideal for security
#     # sshpass -e option uses Password set in Environment Variable "SSHPASS"
#     create_socket_command = f"sshpass -e ssh -N -f -oStrictHostKeyChecking=no -M -S {socket_path} {optional_user_string}{host}"
#     # TODO:  Run the create_socket_command
#     print(create_socket_command)
#     return socket_path


# def kill_socket():
#     """Finds the process that created the Master Socket (-M)
#     and kills it
#     """
#     # TODO:Run find_master_socket_pid_command, and get the output and save as process id
#     kill_master_socket_pid_command = (
#         "ps -ef | grep -v grep | grep -E 'sshpass.+-M' | awk '{print $2}' | xargs kill"
#     )
#     print(kill_master_socket_pid_command)


# def form_ssh_command(command: str, socket_path: str = None):
#     if socket_path is not None:
#         if not os.path.exists(socket_path):
#             raise Exception(f"Socket does not exist at {socket_path}")

#         optional_socket_string = "-S {socket_path}"
#     else:
#         optional_socket_string = ""

#     # TODO:Run the ssh_command_format
#     ssh_command_format = f"ssh {optional_socket_string} USER_HOST_PLACEHOLDER {command}"
