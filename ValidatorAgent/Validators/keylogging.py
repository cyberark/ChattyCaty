import subprocess

# Constants
KEY_LOGGING_QUERY = "WRITE_YOUR_QUERY_HERE"

def check_keylogger():
    # Todo: Implement your keylogging validation here
    raise NotImplemented()


def check_key_logging_func(code):
    print(f"[+] Creates a new process for keylogging ")

    process_object = subprocess.Popen(['python', '-c', code])

    ret_val = check_keylogger()
    
    process_object.terminate()

    if ret_val:
        print("[+] The keylogging was successful!")
        return True
    else:
        print("[+] The keylogging failed!")
