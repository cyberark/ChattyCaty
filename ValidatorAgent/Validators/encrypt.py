import subprocess

ENCRYPT_QUERY = "WRITE_YOUR_QUERY_HERE"

def is_file_encrypted():
    # Todo: Implement your encryption validation here
    raise NotImplemented()

def check_encryption_func(code):
    print(f"[+] Creates a new process for encrypting files")

    process_object = subprocess.Popen(['python', '-c', code])

    ret_val = is_file_encrypted()

    process_object.terminate()

    if ret_val:
        print("[+] The files encryption was successful!")
        return True
    else:
        print("[+] The files encryption failed!")