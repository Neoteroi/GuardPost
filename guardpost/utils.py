import asyncio
import json
import logging
import sys
import urllib.error
import urllib.request


def read_json_data(url: str):
    with urllib.request.urlopen(url) as response:
        return json.loads(response.read())


def get_logger():
    return logging.getLogger("auth-jwts")


def get_running_loop():  # pragma: no cover
    if sys.version_info[:2] <= (3, 7):
        # For Python 3.6
        return asyncio._get_running_loop()
    else:
        return asyncio.get_running_loop()
