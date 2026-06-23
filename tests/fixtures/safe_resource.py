import json


def load_config(path):
    with open(path) as f:
        return json.load(f)


def read_prompt(path):
    with open(path) as f:
        return f.read()


def read_chunk(path, size=4096):
    with open(path, "rb") as f:
        return f.read(size)
