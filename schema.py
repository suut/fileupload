#!/usr/bin/env python3

"""
DEFINITIONS IMPLICIT TAGS ::=
BEGIN

FileType ::= BITSTRING {
    picture (0),
    archive (1),
    pdf     (2),
    text    (4),
    any     (7)
}

Duration ::= INTEGER (0 .. 32767) -- in minutes, maximum 22 days, 18 hours and 7 minutes
ExpirationTime ::= INTEGER

FileUploadAuthenticationRequest ::= [APPLICATION 2] SEQUENCE {
    duration  [0]  Duration,
    fileType  [1]  FileType
}

FileUploadAuthenticationResponse ::= [APPLICATION 3] SEQUENCE {
    expireAt [0]  ExpirationTime,
    fileType [1]  FileType
}

ApplicationRequest ::= CHOICE {
    fileUpload FileUploadAuthenticationRequest
}

ApplicationResponse ::= CHOICE {
    fileUpload FileUploadAuthenticationResponse
}

AuthenticationRequest ::= [APPLICATION 0] SEQUENCE {
    appRequest [0]  EXPLICIT ApplicationRequest
    cSRFToken  [1]  OCTET STRING OPTIONAL
}

Authorization ::= [APPLICATION 1] SEQUENCE {
    appResponse [0]  EXPLICIT ApplicationResponse,
    signature   [1]  OCTET STRING
}

SessionCookieData ::= SEQUENCE {
    sessionId [0]  OCTET STRING
    notBefore [1]  INTEGER,
    notAfter  [2]  INTEGER
}

SessionCookie ::= [APPLICATION 4] SEQUENCE {
    data      [0]  SessionCookieData,
    signature [1]  OCTET STRING
}

END
"""

from pyasn1.type.base import *
from pyasn1.type.univ import *
from pyasn1.type.namedtype import *
from pyasn1.type.namedval import *
from pyasn1.type.tag import *
from pyasn1.type.constraint import *
from pyasn1.error import PyAsn1Error
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.codec.der.decoder import decode as der_decode
from enum import Enum, auto
import base64


class FileType(BitString):
    namedValues = NamedValues(
        ('picture', 1),
        ('archive', 2),
        ('pdf', 4),
        ('text', 8),
        ('any', 15)
    )


class Duration(Integer):
    subtypeSpec = ValueRangeConstraint(0, 32767)


class ExpirationTime(Integer):
    pass


class FileUpload(Sequence):
    tagSet = Sequence.tagSet.tagImplicitly(Tag(tagClassApplication, tagFormatConstructed, 2))

    componentType = NamedTypes(
        NamedType('duration', Duration().subtype(implicitTag=Tag(tagClassContext, tagFormatSimple, 0))),
        NamedType('fileType', FileType().subtype(implicitTag=Tag(tagClassContext, tagFormatSimple, 1)))
    )


class ApplicationRequest(Choice):
    componentType = NamedTypes(
        NamedType('fileUpload', FileUpload())
    )


class AuthenticationRequest(Sequence):
    tagSet = Sequence.tagSet.tagImplicitly(Tag(tagClassApplication, tagFormatConstructed, 0))

    componentType = NamedTypes(
        NamedType('appRequest', ApplicationRequest().subtype(explicitTag=Tag(tagClassContext, tagFormatConstructed, 0))),
        OptionalNamedType('cSRFToken', OctetString().subtype(implicitTag=Tag(tagClassContext, tagFormatSimple, 1)))
    )


class FileUploadAuthenticationResponse(Sequence):
    tagSet = Sequence.tagSet.tagImplicitly(Tag(tagClassApplication, tagFormatConstructed, 3))
    componentType = NamedTypes(
        NamedType('expireAt', ExpirationTime().subtype(implicitTag=Tag(tagClassContext, tagFormatSimple, 0))),
        NamedType('fileType', FileType().subtype(implicitTag=Tag(tagClassContext, tagFormatSimple, 1)))
    )


class ApplicationResponse(Choice):
    componentType = NamedTypes(
        NamedType('fileUpload', FileUploadAuthenticationResponse())
    )


class Authorization(Sequence):
    tagSet = Sequence.tagSet.tagImplicitly(Tag(tagClassApplication, tagFormatConstructed, 1))

    componentType = NamedTypes(
        NamedType('appResponse', ApplicationResponse().subtype(explicitTag=Tag(tagClassContext, tagFormatConstructed, 0))),
        NamedType('signature', OctetString().subtype(implicitTag=Tag(tagClassContext, tagFormatSimple, 1)))
    )


class SessionCookieData(Sequence):
    componentType = NamedTypes(
        NamedType('sessionId', OctetString().subtype(implicitTag=Tag(tagClassContext, tagFormatSimple, 0))),
        NamedType('notBefore', Integer().subtype(implicitTag=Tag(tagClassContext, tagFormatSimple, 1))),
        NamedType('notAfter', Integer().subtype(implicitTag=Tag(tagClassContext, tagFormatSimple, 2)))
    )


class SessionCookie(Sequence):
    tagSet = Sequence.tagSet.tagImplicitly(Tag(tagClassApplication, tagFormatConstructed, 4))

    componentType = NamedTypes(
        NamedType('data', SessionCookieData().subtype(implicitTag=Tag(tagClassContext, tagFormatConstructed, 0))),
        NamedType('signature', OctetString().subtype(implicitTag=Tag(tagClassContext, tagFormatSimple, 1))),
    )


class Encoding(Enum):
    urlsafe_base64 = auto()
    base32 = auto()


def base64_urlsafe_nopad_encode(x: bytes) -> str:
    return base64.urlsafe_b64encode(x)[:(len(x) * 8 + 5) // 6].decode('ascii')


def base64_urlsafe_nopad_decode(x: str) -> bytes:
    return base64.urlsafe_b64decode(x.encode('ascii') + (-len(x) % 4) * b'=')


def base32_nopad_encode(x: bytes) -> str:
    return base64.b32encode(x)[:(len(x) * 8 + 4) // 5].decode('ascii')


def base32_nopad_decode(x: str) -> bytes:
    return base64.b32decode(x.encode('ascii') + (-len(x) % 8) * b'=')


def encode(req: Asn1Type, encoding: Encoding) -> str:
    encoded = der_encode(req)
    match encoding:
        case Encoding.urlsafe_base64:
            return base64_urlsafe_nopad_encode(encoded)
        case Encoding.base32:
            return base32_nopad_encode(encoded)
        case _:
            raise ValueError('Invalid encoding')


def decode(data: str, schema: Asn1Type, encoding: Encoding) -> Asn1Type:
    match encoding:
        case Encoding.urlsafe_base64:
            raw = base64_urlsafe_nopad_decode(data)
        case Encoding.base32:
            raw = base32_nopad_decode(data)
        case _:
            raise ValueError('Invalid encoding')
    obj, rest = der_decode(raw, asn1Spec=schema)
    if rest != b'':
        raise PyAsn1Error()
    return obj
