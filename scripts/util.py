#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import logging
import argparse
from pathlib import Path
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("party")


_DEFAULT_TIMEOUT = 15  # seconds


def _build_session():
    session = requests.Session()
    retry = Retry(
        total=3,
        read=3,
        connect=3,
        status=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST"]),
        raise_on_status=False,
    )

    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session

_session = _build_session()

def _raise_for_status(resp):
    try:
        resp.raise_for_status()
        return resp
    except requests.HTTPError as e:
        snippet = resp.text[:500] if resp.text else ""
        raise requests.HTTPError(f"{e} | body: {snippet}")

def http_get(url, params=None, headers=None, timeout=_DEFAULT_TIMEOUT):
    log.info("GET %s", url)
    resp = _session.get(url, params=params, headers=headers, timeout=timeout)
    return _raise_for_status(resp)

def http_post_json(url, json_body, headers=None, timeout=_DEFAULT_TIMEOUT):
    headers = {"Content-Type": "application/json", **(headers or {})}
    log.info("POST %s JSON %d bytes", url, len(json.dumps(json_body)))
    resp = _session.post(url, json=json_body, headers=headers, timeout=timeout)
    return _raise_for_status(resp)

def http_post_form(url, form_fields, headers=None, timeout=_DEFAULT_TIMEOUT):
    headers = {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})}
    log.info("POST %s FORM %d fields", url, len(form_fields))
    resp = _session.post(url, data=form_fields, headers=headers, timeout=timeout)
    return _raise_for_status(resp)

def http_post_multipart(url, file_path, field_name="file", extra_fields=None, headers=None, timeout=_DEFAULT_TIMEOUT):
    p = Path(file_path)
    if not p.is_file():
        raise FileNotFoundError(f"file not found: {p}")

    files = {field_name: (p.name, p.open("rb"))}
    data = extra_fields or {}

    log.info("POST %s MULTIPART file=%s size=%d", url, p.name, p.stat().st_size)

    try:
        resp = _session.post(url, files=files, data=data, headers=headers, timeout=timeout)
        return _raise_for_status(resp)
    finally:
        files[field_name][1].close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Party")
    parser.add_argument("base_url", help="Base URL")
    parser.add_argument("client_id", help="Client ID")
    args = parser.parse_args()

    base_url = args.base_url
    client_id = args.client_id

    try:
        print(base_url, client_id)
    except Exception as e:
        log.error("error: %s", e)

