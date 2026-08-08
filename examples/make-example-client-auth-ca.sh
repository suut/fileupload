#!/bin/bash

# Make the CA
echo Making the client auth CA

openssl req -x509 -new -newkey EC -keyout clientauth-ca.key -noenc -pkeyopt ec_paramgen_curve:P-384 -sha384 -subj '/CN=Client auth CA' -out clientauth-ca.pem \
    -addext basicConstraints=critical,CA:TRUE

echo Client auth CA certificate: "$(realpath clientauth-ca.pem)"
echo Client auth CA private key: "$(realpath clientauth-ca.key)"

echo
echo Issuing a client certificate

openssl req -x509 -new -newkey EC -keyout clientauth.key -noenc -pkeyopt ec_paramgen_curve:P-384 -sha384 -subj '/CN=Client auth certificate' -out clientauth.pem \
    -CA clientauth-ca.pem -CAkey clientauth-ca.key \
    -addext basicConstraints=critical,CA:FALSE \
    -addext keyUsage=critical,digitalSignature \
    -addext extendedKeyUsage=clientAuth

echo Client auth certificate: "$(realpath clientauth.pem)"
echo Client auth key: "$(realpath clientauth.key)"

echo
echo Making the .pfx bundle

openssl pkcs12 -in clientauth.pem -export -inkey clientauth.key -CAfile clientauth-ca.pem -chain -out clientauth.pfx

echo PFX file to load into the browser: "$(realpath clientauth.pfx)"
