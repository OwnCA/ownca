#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2020 Kairo de Araujo
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.rsa import (
    _RSAPrivateKey,
    _RSAPublicKey,
)
from voluptuous import Schema, MultipleInvalid

from ownca.exceptions import OwnCAInvalidDataStructure


def _validate_owncakeydata(key_data):
    key_schema = Schema(
        {
            "key": _RSAPrivateKey,
            "key_bytes": bytes,
            "public_key": _RSAPublicKey,
            "public_key_bytes": bytes,
        }
    )

    try:
        key_schema(key_data)

    except MultipleInvalid as err:
        raise OwnCAInvalidDataStructure("OwncaKeyData: " + str(err))


class OwncaKeyData(object):
    """
     Generates Ownca Key Data Structure

     :param key_data: Key Data

        .. highlight:: python
        .. code-block:: python

         {
             "key": cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey,
             "key_bytes": bytes,
             "public_key":
                 cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey,
             "public_key_bytes": bytes,
         }
     :type key_data: dict

     :return: OwncaKeyData
     :rtype: ``ownca.crypto.keys.OwncaKeyData``
     :raises: ``OwnCAInvalidDataStructure``
     """
    def __init__(self, key_data):
        try:
            _validate_owncakeydata(key_data)

        except OwnCAInvalidDataStructure as err:
            raise err

        self.__dict__ = key_data
        self.key_data = key_data

    @property
    def key(self):
        """
        Method to get the key

        :return: key
        :rtype: ``cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey``
        """
        return self.key_data["key"]

    @property
    def key_bytes(self):
        """
        Method to get the key in ``bytes``

        :return: key
        :rtype: bytes
        """
        return self.key_data["key_bytes"]

    @property
    def public_key(self):
        """
        Method to get the public key

        :return: key
        :rtype: ``cryptography.hazmat.backends.openssl.rsa._RSAPublicKey``
        """
        return self.key_data["public_key"]

    @property
    def public_key_bytes(self):
        """
        Method to get the public key in ``bytes``

        :return: public key
        :rtype: bytes
        """
        return self.key_data["public_key_bytes"]


def _get_public_key(key):
    """
    Extract the public key from key object as string.

    :param key: key object
        ``cryptography.hazmat.backends.openssl.rsa._RSAPublicKey``
    :type key: object, required.

    :return: public key as string
    :rtype: string
    """
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

    :return: Ownca Key Data Structure
    :rtype: ``ownca.crypto.keys.OwncaKeyData``
    """

    key = rsa.generate_private_key(
        backend=default_backend(),
        public_exponent=public_exponent,
        key_size=key_size,
    )

    key_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    public_key = key.public_key()

    public_key_bytes = _get_public_key(key)

    return OwncaKeyData(
        {
            "key": key,
            "key_bytes": key_bytes,
            "public_key": public_key,
            "public_key_bytes": public_key_bytes,
        }
    )
