#!/usr/bin/env python3
import binascii
import time
from pathlib import Path
import hmac
import base64

import pytoml
from pyasn1.codec.der.encoder import encode as der_encode
from aiohttp import web
from pyasn1.error import PyAsn1Error

import schema
import session


ROOTDIR = Path(__file__).parent

CONFIG_FILE = ROOTDIR / 'config.toml'


config = pytoml.loads(CONFIG_FILE.read_text())


routes = web.RouteTableDef()


@routes.get('/favicon.ico')
async def favicon(request: web.Request) -> web.Response:
    raise web.HTTPNotFound()


@routes.get('/api/authenticate/{token}')
async def index(request: web.Request) -> web.Response:
    if config['auth']['verify_referrer'] and not request.headers.get('Referer', '').startswith(config['fileupload']['base_url']):
        raise web.HTTPForbidden()

    token = request.match_info['token']
    try:
        req = schema.decode(token, schema.AuthenticationRequest(), schema.Encoding.urlsafe_base64)
    except (PyAsn1Error, binascii.Error):
        raise web.HTTPForbidden()

    if config['auth']['use_csrf']:
        if '__Http-_sid' not in request.cookies:
            raise web.HTTPForbidden()
        try:
            session_id = session.get_session_id(request)
        except (PyAsn1Error, binascii.Error):
            raise web.HTTPForbidden()
        if not req['cSRFToken'].hasValue():
            raise web.HTTPForbidden()
        if not session.check_csrf_token(session_id, req['cSRFToken'].asOctets(), 'authentication'):
            raise web.HTTPForbidden()

    now = time.time() // 60
    expire_at = now + int(req['appRequest']['fileUpload']['duration'])

    authorization = schema.Authorization()
    authorization['appResponse']['fileUpload']['expireAt'] = expire_at
    authorization['appResponse']['fileUpload']['fileType'] = req['appRequest']['fileUpload']['fileType']

    encoded_parameters = der_encode(authorization['appResponse'])

    match config['auth']['algo']:
        case 'hmac':
            digest = hmac.digest(base64.b64decode(config['auth']['hmac']['secret_key']), encoded_parameters, config['auth']['hmac']['digest'])
            authorization['signature'] = digest[:config['auth']['hmac']['length']]
        case _:
            raise web.HTTPServerError()

    encoded_authorization = schema.encode(authorization, schema.Encoding[config['auth']['encoding']])

    resp = web.Response(status=303)
    resp.headers['Location'] = f'{config["fileupload"]["base_url"]}/t/{encoded_authorization}'
    return resp


app = web.Application()
app.add_routes(routes)
web.run_app(app, host=config['auth']['responder']['listen_address'], port=config['auth']['responder']['port'], reuse_address=True)
