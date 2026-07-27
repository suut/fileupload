#!/usr/bin/env python3

from pathlib import Path
import hmac
import base64
import sys
import datetime
import binascii

from aiohttp import web
import pytoml
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.error import PyAsn1Error
import aiohttp_jinja2
import jinja2

import schema
import session


ROOTDIR = Path(__file__).parent

CONFIG_FILE = ROOTDIR / 'config.toml'


config = pytoml.loads(CONFIG_FILE.read_text())


routes = web.RouteTableDef()


@routes.get('/favicon.ico')
async def favicon(request: web.Request) -> web.Response:
    raise web.HTTPNotFound()


@routes.get('/')
async def index(request: web.Request) -> web.Response:
    print('/:', request.headers)
    response = aiohttp_jinja2.render_template('index.jinja2', request, {})
    return response


@routes.get('/request-token')
async def request_token(request: web.Request) -> web.Response:
    print('/request-token:', request.headers)

    if config['auth']['verify_referrer'] and not request.headers.get('Referer', '').startswith(config['fileupload']['base_url']):
        raise web.HTTPForbidden()

    session_valid = False
    session_id = None
    new_cookie = None
    if config['auth']['use_csrf']:
        if '__Http-_sid' in request.cookies:
            try:
                session_id, session_valid = session.get_session_id_and_validity(request.cookies['__Http-_sid'])
            except (PyAsn1Error, binascii.Error):
                session_id, session_valid = None, False

        if not session_valid:
            session_id, new_cookie = session.make_session_cookie()

    resp = web.Response()

    if new_cookie:
        resp.set_cookie('__Http-_sid', new_cookie, domain=config['top_level_domain'], samesite='Lax', secure=True, httponly=True)

    # Make an authorization request for 30 minutes
    req = schema.AuthenticationRequest()
    req['appRequest']['fileUpload']['duration'] = 30
    req['appRequest']['fileUpload']['fileType'] = schema.FileType.namedValues['any']
    if config['auth']['use_csrf']:
        req['cSRFToken'] = session.derive_csrf_token(session_id)
    encoded_req = schema.encode(req, schema.Encoding.urlsafe_base64)

    resp.headers['Location'] = config['auth']['auth_base_url'] + '/' + encoded_req
    resp.headers['Referrer-Policy'] = 'origin'
    resp.set_status(307)

    return resp

@routes.get('/{token}')
async def token(request: web.Request) -> web.Response:
    print('/{token}:', request.headers)

    if config['auth']['verify_referrer'] and not request.headers.get('Referer', '').startswith(config['fileupload']['base_url']):
        raise web.HTTPForbidden()

    # decode token and verify it
    try:
        response = schema.decode(request.match_info['token'], schema.Authorization(), schema.Encoding[config['auth']['encoding']])
    except (PyAsn1Error, binascii.Error):
        raise web.HTTPForbidden()

    signed_data = der_encode(response['appResponse'])

    # check signature
    match config['auth']['algo']:
        case 'hmac':
            digest = hmac.digest(base64.b64decode(config['auth']['hmac']['secret_key']), signed_data, config['auth']['hmac']['digest'])
            digest = digest[:config['auth']['hmac']['length']]
            assert hmac.compare_digest(digest, response['signature'].asOctets())
        case _:
            sys.exit('Invalid algo')

    return web.Response(text='Authorization valid until: ' + str(datetime.datetime.fromtimestamp(60 * int(response['appResponse']['fileUpload']['expireAt']))))

app = web.Application()
aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader(str(ROOTDIR / 'templates')))
app.add_routes(routes)
web.run_app(app, host='127.0.1.1', port=8080, reuse_address=True)
