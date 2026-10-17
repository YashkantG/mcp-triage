import os
import pickle
import subprocess
from subprocess import run as aliased_run

AWS_KEY = "AKIAABCDEFGHIJKLMNOP"


def run_command(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()


def load_data(raw: bytes):
    return pickle.loads(raw)


def handler(user_input: str):
    return eval(user_input)


def legacy_handler(user_input: str):
    return os.system(user_input)


def aliased_command(user_input: str):
    return aliased_run(
        user_input,
        shell=True,
    )
