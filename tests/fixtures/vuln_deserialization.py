import yaml


def load_config(path):
    with open(path) as f:
        return yaml.load(f)


def load_unsafe(data):
    return yaml.unsafe_load(data)
