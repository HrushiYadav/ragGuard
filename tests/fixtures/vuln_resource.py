import pickle
import zipfile


def load_data(path):
    with open(path, "rb") as f:
        return pickle.load(f)


def extract_backup(zip_path, dest):
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest)
