import openai
from contextlib import contextmanager
import os
import logging
from Utilities.ImportSolver import *

OPENAI_KEY = "INSERT_YOUR_OPENAI_API_KEY_HERE"

class MessageWriter(object):
    def __init__(self, filename):
        self.file_name = filename

    @contextmanager
    def open_file(self):
        try:
            file = open(self.file_name, 'a')
            yield file
        finally:
            file.close()

    def delete_file(self):
        try:
            os.remove(self.file_name)
        except:
            pass


class ChatGPT:
    def __init__(self, api_key=OPENAI_KEY):
        self.api_key = api_key
        openai.api_key = api_key

    def chat(self, prompt):
        logging.debug(f"[+] Asking davinci to: {prompt}")
        completions = openai.Completion.create(
            engine="text-davinci-003",
            prompt=prompt,
            max_tokens=1024,
            n=5,
            stop=None,
            temperature=0.65,
        )

        code_snippets = []

        for index, code_response in enumerate(completions.choices):
            code_snippets.append(code_response.text)
            logging.debug(f"[+] Response {index}: {code_response}")

        return code_snippets

    def query_and_check(self, query, validation_func):
        # 20*5 => 100 different function options should be enough
        for i in range(20):
            try:

                resp_list = self.chat(query)

                for resp in resp_list:
                    code = resp
                    compile(code, "tmpfile", "exec")

                    resolve_imports(code)

                    check_result = validation_func(code)

                    if check_result:
                        return True, code

            except Exception as e:
                print(f"Exception occurred: {e}")
                continue

        return False, None
