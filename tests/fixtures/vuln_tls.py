import requests
import ssl


def fetch_insecure():
    return requests.get("https://api.example.com", verify=False)


def bad_context():
    ctx = ssl._create_unverified_context()
    return ctx
