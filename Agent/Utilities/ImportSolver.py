from modulefinder import ModuleFinder
import types
import subprocess
import time


def get_list_of_imports_from_code_string(code_str):
    # Compile the code string into a code object
    code_obj = compile(code_str, "tmpfile", "exec")

    # Create a module to contain the dynamic code
    module = types.ModuleType("my_module")

    # Create a ModuleFinder instance and run it on the dynamic code
    finder = ModuleFinder()

    import_modules = set()

    for what, args in finder.scan_opcodes(code_obj):
        if "absolute_import" == what:
            from_list, base_module_name = args
            print(f"Base module => {base_module_name}")
            import_modules.add(base_module_name)

    return list(import_modules)


def resolve_imports(code_str):
    import_list = get_list_of_imports_from_code_string(code_str)

    for module_import in import_list:
        try:
            __import__(module_import)
        except Exception as e:
            print(f"Failed to import {module_import}, trying to install it using pip")
            proc = subprocess.Popen(["python", "-m", "pip", "install", module_import])

            while proc.poll() is None:
                print("Process is still running...")
                time.sleep(1)

            # Seconds try
            try:
                __import__(module_import)
            except Exception as e:
                return False

    return True
