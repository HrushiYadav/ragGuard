import httpx
import requests


def get_config():
    return requests.get("https://api.example.com/config")


def post_health():
    return httpx.post("https://api.example.com/health", json={})


def dict_lookup(d, key):
    return d.get(key, None)
