#!/usr/bin/env python3
import asyncio
import json
import os
import time
from pathlib import Path
import hmac
import base64
import sys
import datetime
import binascii
import tempfile
import re

import aiohttp.multipart
from aiohttp import web
import pytoml
from aiohttp.web_response import json_response
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.error import PyAsn1Error
import aiohttp_jinja2
import jinja2

import schema
import session


ROOTDIR = Path(__file__).parent

CONFIG_FILE = ROOTDIR / 'config.toml'


config = pytoml.loads(CONFIG_FILE.read_text())


TMPDIR = Path(ROOTDIR / config['fileupload']['temporary_directory'])
TMPDIR.mkdir(exist_ok=True)

OUTPUT_PRIVATE = ROOTDIR / config['fileupload']['output']['private_dir']
OUTPUT_PUBLIC = ROOTDIR / config['fileupload']['output']['public_dir']

OUTPUT_PRIVATE.mkdir(parents=True, exist_ok=True)
OUTPUT_PUBLIC.mkdir(parents=True, exist_ok=True)

routes = web.RouteTableDef()


@routes.get('/')
async def index(request: web.Request) -> web.Response:
    style_nonce = schema.make_nonce(config['fileupload']['css_nonce_length'])
    script_nonce = schema.make_nonce(config['fileupload']['javascript_nonce_length'])

    ctx = {
        'style_nonce': style_nonce,
        'script_nonce': script_nonce
    }

    new_cookie = None
    if config['auth']['use_csrf']:
        session_id, new_cookie = session.get_or_create_session(request)
        ctx['csrf_token'] = schema.base64_urlsafe_nopad_encode(session.derive_csrf_token(session_id, 'auth-form'))

    response = aiohttp_jinja2.render_template('index.jinja2', request, ctx)
    if config['auth']['use_csrf'] and new_cookie is not None:
        response.set_cookie('__Http-_sid', new_cookie, domain=config['top_level_domain'], samesite='Lax', secure=True,
                            httponly=True)
    response.headers['Content-Security-Policy'] = f"style-src 'nonce-{style_nonce}'; script-src 'nonce-{script_nonce}'"
    response.headers['Referrer-Policy'] = 'origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-site'
    return response


@routes.post('/request-token')
async def request_token(request: web.Request) -> web.Response:
    if config['auth']['verify_referrer'] and not request.headers.get('Referer', '').startswith(config['fileupload']['base_url']):
        raise web.HTTPForbidden()

    data = await request.post()

    if 'filetype' not in data or data['filetype'] not in schema.FileType.namedValues:
        raise web.HTTPForbidden()

    if 'duration' not in data or not all(c in '0123456789' for c in data['duration']):
        raise web.HTTPForbidden()

    if 'access_mode' not in data or data['access_mode'] not in schema.AccessMode.namedValues:
        raise web.HTTPForbidden()

    if config['auth']['use_csrf']:
        if 'csrf_token' not in data:
            raise web.HTTPForbidden()
        session.check_csrf_token(session.get_session_id(request), schema.base64_urlsafe_nopad_decode(data['csrf_token']), 'auth-form')

    req = schema.AuthenticationRequest()
    req['duration'] = int(data['duration'])
    req['appRequest']['fileUpload']['fileType'] = schema.FileType.namedValues[data['filetype']]
    req['appRequest']['fileUpload']['accessMode'] = schema.AccessMode.namedValues[data['access_mode']]
    if config['auth']['use_csrf']:
        req['cSRFToken'] = session.derive_csrf_token(session.get_session_id(request), 'authentication')
    encoded_req = schema.encode(req, schema.Encoding.urlsafe_base64)

    response = web.Response(status=303)
    response.headers['Location'] = f'{config["auth"]["auth_base_url"]}/api/authenticate/{encoded_req}'
    response.headers['Referrer-Policy'] = 'origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-site'

    return response


def decode_and_verify_token(token):
    # decode token and verify it
    try:
        auth = schema.decode(token, schema.Authorization(), schema.Encoding[config['auth']['encoding']])
    except (PyAsn1Error, binascii.Error):
        raise web.HTTPForbidden()

    signed_data = der_encode(auth['appResponse'])

    # check signature
    match config['auth']['algo']:
        case 'hmac':
            digest = hmac.digest(base64.b64decode(config['auth']['hmac']['secret_key']), signed_data, config['auth']['hmac']['digest'])
            digest = digest[:config['auth']['hmac']['length']]
            if not hmac.compare_digest(digest, auth['signature'].asOctets()):
                raise web.HTTPForbidden()
        case algo:
            print('Invalid algo', algo, file=sys.stderr)
            raise web.HTTPForbidden()

    # check validity
    if 60 * auth['expiration'] < time.time():
        raise web.HTTPForbidden()

    return auth


@routes.get('/t/{token}')
async def token(request: web.Request) -> web.Response:
    auth = decode_and_verify_token(request.match_info['token'])

    style_nonce = schema.make_nonce(config['fileupload']['css_nonce_length'])
    script_nonce = schema.make_nonce(config['fileupload']['javascript_nonce_length'])

    response = aiohttp_jinja2.render_template('upload.jinja2', request, {
        'access_modes': schema.AccessMode.namedValues,
        'file_types': schema.FileType.namedValues,
        'expire_at': str(datetime.datetime.fromtimestamp(60 * int(auth['expiration']))),
        'file_type': auth['appResponse']['fileUpload']['fileType'].asInteger(),
        'token': request.match_info['token'],
        'access_mode': auth['appResponse']['fileUpload']['accessMode'],
        'style_nonce': style_nonce,
        'script_nonce': script_nonce,
        'url': f'{config["fileupload"]["base_url"]}/t/{request.match_info["token"]}'
    })

    response.headers['Content-Security-Policy'] = f"style-src 'nonce-{style_nonce}'; script-src 'nonce-{script_nonce}'"
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-site'

    return response


async def read_multipart(f, field: aiohttp.multipart.BodyPartReader, short_timeout: int|float, long_timeout: int|float, chunk_size:int = 4096):
    try:
        async with asyncio.timeout(long_timeout):
            while not field.at_eof():
                async with asyncio.timeout(short_timeout):
                    f.write(await field.read_chunk(chunk_size))
    except TimeoutError:
        raise web.HTTPRequestTimeout()


@routes.post('/t/{token}')
async def post(request: web.Request) -> web.Response:
    auth = decode_and_verify_token(request.match_info['token'])

    if request.content_type != 'multipart/form-data':
        raise web.HTTPForbidden()

    reader: aiohttp.multipart.MultipartReader|None = await request.multipart()
    if reader is None:
        raise web.HTTPForbidden()

    found_fields = set()
    tmp = tempfile.NamedTemporaryFile(dir=TMPDIR, delete=False, delete_on_close=False, suffix='.tmp')
    tmp_filename = tmp.name
    filename = None
    metadata = None
    encrypted = False
    try:
        while True:
            field: aiohttp.multipart.BodyPartReader|aiohttp.multipart.MultipartReader|None = await reader.next()
            if field is None:
                break
            if not isinstance(field, aiohttp.multipart.BodyPartReader):
                raise web.HTTPForbidden()
            match field.name:
                case 'metadata':
                    metadata = await field.text(encoding='utf-8')
                    print(f'Metadata policy: {metadata!r}')

                case 'file':
                    if not field.filename:
                        raise web.HTTPForbidden()  # empty file or no filename

                    filename = field.filename

                    if field.filename in ('.', '..') or '/' in field.filename:
                        raise web.HTTPForbidden()

                    await read_multipart(tmp, field, config['fileupload']['recv_chunk_timeout'],
                                         config['fileupload']['recv_file_timeout'])
                    tmp.close()

                case 'encrypted':
                    if await field.text(encoding='utf-8') == 'true':
                        encrypted = True

                case x:
                    raise web.HTTPForbidden()
            found_fields.add(field.name)
        if 'file' not in found_fields:
            raise web.HTTPForbidden()

    except web.HTTPException:
        os.unlink(tmp_filename)
        raise
    except:
        os.unlink(tmp_filename)
        raise web.HTTPForbidden()

    # TODO: remove metadata

    orig_stem, sep, suffix = filename.partition('.')
    stem = orig_stem + '-' + os.urandom(4).hex()

    if auth['appResponse']['fileUpload']['accessMode'] == schema.AccessMode.namedValues['public']:
        outdir = OUTPUT_PUBLIC
        base_url = config['fileupload']['output']['public_base_url']
    else:  # private
        outdir = OUTPUT_PRIVATE
        base_url = config['fileupload']['output']['private_base_url']

    while (outfile := outdir / (stem + sep + suffix)).exists():
        stem = orig_stem + '-' + os.urandom(4).hex()

    os.rename(tmp_filename, str(outfile))
    outfile.chmod(0o644)

    if encrypted:
        if auth['appResponse']['fileUpload']['accessMode'] == schema.AccessMode.namedValues['public']:
            return web.json_response(text=json.dumps({'url': f'{config["fileupload"]["base_url"]}/enc/pub/{outfile.name}'}))
        else:
            return web.json_response(text=json.dumps({'url': f'{config["fileupload"]["base_url"]}/enc/priv/{outfile.name}'}))

    else:
        style_nonce = schema.make_nonce(config['fileupload']['css_nonce_length'])
        script_nonce = schema.make_nonce(config['fileupload']['javascript_nonce_length'])

        response = aiohttp_jinja2.render_template('success.jinja2', request, {
            'style_nonce': style_nonce,
            'script_nonce': script_nonce,
            'url': f'{base_url}/{outfile.name}'
        })

        response.headers['Content-Security-Policy'] = f"style-src 'nonce-{style_nonce}'; script-src 'nonce-{script_nonce}'"
        response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Resource-Policy'] = 'same-site'

        return response


@routes.get('/enc/{kind}/{filename}')
def get_encrypted(request: web.Request) -> web.Response:
    match request.match_info['kind']:
        case 'pub':
            filedir = OUTPUT_PUBLIC
            base_url = config['fileupload']['output']['public_base_url']
        case 'priv':
            filedir = OUTPUT_PRIVATE
            base_url = config['fileupload']['output']['private_base_url']
        case _:
            raise web.HTTPForbidden()

    filename = request.match_info['filename']
    if not (filedir / filename).exists():
        raise web.HTTPForbidden()
    file_url = f'{base_url}/{filename}'

    style_nonce = schema.make_nonce(config['fileupload']['css_nonce_length'])
    script_nonce = schema.make_nonce(config['fileupload']['javascript_nonce_length'])

    response = aiohttp_jinja2.render_template('encrypted.jinja2', request, {
        'style_nonce': style_nonce,
        'script_nonce': script_nonce,
        'file_url': file_url,
        'url': f'{config["fileupload"]["base_url"]}/enc/{request.match_info["kind"]}/{filename}',
        'filename': filename
    })

    response.headers['Content-Security-Policy'] = f"style-src 'nonce-{style_nonce}'; script-src 'nonce-{script_nonce}'"
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-site'

    return response


def mask(a, b):
    return a & b


suffixes = {
    'k': 1024,
    'm': 1024**2,
    'g': 1024**3,
    'kib': 1024,
    'mib': 1024**2,
    'gib': 1024**3,
    'kb': 1024,
    'mb': 1024**2,
    'gb': 1024**3
}

if isinstance(config['fileupload']['max_size'], int):
    max_size = config['fileupload']['max_size']
elif isinstance(config['fileupload']['max_size'], str):
    try:
        size_str, suffix = re.split(r'(?=[^0-9])', config['fileupload']['max_size'].strip(), maxsplit=1)
        max_size = int(size_str) * suffixes[suffix.lower().strip()]
    except (ValueError, KeyError):
        print('Malformed fileupload.max_size in configuration', file=sys.stderr)
        sys.exit(1)
else:
    print('Invalid type for fileupload.max_size in configuration', file=sys.stderr)
    sys.exit(1)

app = web.Application(client_max_size=max_size)
aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader(str(ROOTDIR / 'templates')), filters={
    'mask': mask,
})
app.add_routes(routes)
web.run_app(app, host=config['fileupload']['listen_address'], port=config['fileupload']['port'], reuse_address=True)
