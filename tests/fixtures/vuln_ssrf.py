import requests


def fetch_url(user_url):
    return requests.get(f"https://api.example.com/{user_url}/data")


def fetch_profile(username):
    return requests.post(f"https://service.internal/{username}")
