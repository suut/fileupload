#!/usr/bin/env python3

import os
import time
import hmac
import base64
import binascii
from pathlib import Path

from aiohttp import web
from pyasn1.codec.der.encoder import encode as der_encode
import pytoml
from pyasn1.error import PyAsn1Error

import schema



ROOTDIR = Path(__file__).parent

CONFIG_FILE = ROOTDIR / 'config.toml'


config = pytoml.loads(CONFIG_FILE.read_text())


def get_session_id(req: web.Request) -> bytes:
    if (key := '__Http-_sid') not in req.cookies:
        raise web.HTTPForbidden()
    s = req.cookies[key]
    cookie = schema.decode(s, schema.SessionCookie(), schema.Encoding.urlsafe_base64)
    signed_data = der_encode(cookie['data'])
    digest = hmac.digest(base64.b64decode(config['session']['secret_key']), signed_data, config['session']['digest'])[:config['session']['hmac_length']]
    digest_ok = hmac.compare_digest(digest, cookie['signature'].asOctets())

    valid = digest_ok and cookie['data']['notBefore'] <= int(time.time()) <= cookie['data']['notAfter']
    if not valid:
        raise web.HTTPForbidden()
    return cookie['data']['sessionId'].asOctets()


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


def derive_csrf_token(session_id: bytes, label: str) -> bytes:
    return hmac.digest(base64.b64decode(config['auth']['csrf']['secret_key']),
                       label.encode('utf-8') + b'\x00' + session_id,
                       config['auth']['csrf']['digest'])[:config['auth']['csrf']['hmac_length']]


def check_csrf_token(session_id: bytes, csrf_token: bytes, label: str) -> bool:
    digest = derive_csrf_token(session_id, label)
    return hmac.compare_digest(digest, csrf_token)


def make_or_create_session(request: web.Request) -> tuple[bytes, str|None]:
    session_valid = False
    session_id = None
    new_cookie = None
    if '__Http-_sid' in request.cookies:
        try:
            session_id = get_session_id(request)
            session_valid = True
        except (PyAsn1Error, binascii.Error, web.HTTPClientError):
            session_id, session_valid = None, False

    if not session_valid:
        session_id, new_cookie = make_session_cookie()

    return session_id, new_cookie
