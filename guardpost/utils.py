import json
import logging
import urllib.error
import urllib.request


def read_json_data(url: str):
    with urllib.request.urlopen(url) as response:
        return json.loads(response.read())


def get_logger():
    return logging.getLogger("auth-jwts")
