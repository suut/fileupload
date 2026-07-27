#!/usr/bin/env python3

import os
import time
import hmac
import base64
from pathlib import Path

from pyasn1.codec.der.encoder import encode as der_encode
import pytoml

import schema



ROOTDIR = Path(__file__).parent

CONFIG_FILE = ROOTDIR / 'config.toml'


config = pytoml.loads(CONFIG_FILE.read_text())


def get_session_id_and_validity(s: str) -> tuple[bytes, bool]:
    cookie = schema.decode(s, schema.SessionCookie(), schema.Encoding.urlsafe_base64)
    signed_data = der_encode(cookie['data'])
    digest = hmac.digest(base64.b64decode(config['session']['secret_key']), signed_data, config['session']['digest'])[:config['session']['hmac_length']]
    digest_ok = hmac.compare_digest(digest, cookie['signature'].asOctets())

    valid = digest_ok and cookie['data']['notBefore'] <= int(time.time()) <= cookie['data']['notAfter']
    return cookie['data']['sessionId'].asOctets(), valid


def make_session_cookie() -> tuple[bytes, str]:
    session_id = os.urandom(config['session']['session_id_length'])
    cookie = schema.SessionCookie()
    cookie['data']['sessionId'] = session_id
    cookie['data']['notBefore'] = int(time.time())
    cookie['data']['notAfter'] = int(time.time() + config['session']['expiration_time'])
    to_sign = der_encode(cookie['data'])
    digest = hmac.digest(base64.b64decode(config['session']['secret_key']), to_sign, config['session']['digest'])
    cookie['signature'] = digest[:config['session']['hmac_length']]

    return session_id, schema.encode(cookie, schema.Encoding.urlsafe_base64)


def derive_csrf_token(session_id: bytes) -> bytes:
    return hmac.digest(base64.b64decode(config['auth']['csrf']['secret_key']),
                       session_id,
                       config['auth']['csrf']['digest'])[:config['auth']['csrf']['hmac_length']]


def check_csrf_token(session_id: bytes, csrf_token: bytes) -> bool:
    digest = derive_csrf_token(session_id)
    return hmac.compare_digest(digest, csrf_token)
