import subprocess

PERSISTENCE_QUERY = "WRITE_YOUR_QUERY_HERE"

def check_persistence(key, sub_key, value):
    # Todo: Implement your persistence validation here
    raise NotImplemented()


def check_persistence_func(code):
    print(f"[+] Creates a new process for keylogging ")

    process_object = subprocess.Popen(['python', '-c', code])

    ret_val = check_persistence()
    
    process_object.terminate()

    if ret_val:
        print("[+] The keylogging was successful!")
        return True
    else:
        print("[+] The keylogging failed!")