#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2020 Kairo de Araujo
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def _get_public_key(key):
    return key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )


def generate(public_exponent=65537, key_size=2048):
    """
    Generates Private and Public keys

    :param public_exponent: Public Exponent
    :type public_exponent: int, optional, Default: 65537
    :param key_size: Key size
    :type key_size: int, optional, Default: 2048
    :return: RSA Private Key class, Private key bytes,
        RSA Public Key classes, Public key bytes
    :rtype: tuple, (
        ``cryptography.hazmat.backends.openssl.rsa.RSAPrivateKey``,
        Private key bytes,
        ``cryptography.hazmat.backends.openssl.rsa.RSAPublicKey``,
        Public key bytes
        )
    """
    key = rsa.generate_private_key(
        backend=default_backend(),
        public_exponent=public_exponent,
        key_size=key_size,
    )

    private_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    pem_public_key = key.public_key()

    public_key = _get_public_key(key)

    return key, private_key, pem_public_key, public_key
