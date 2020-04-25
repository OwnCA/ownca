# -*- coding: utf-8 -*-
"""
Copyright (c) 2020 Kairo de Araujo
"""
from unittest import mock

from ownca.crypto.keys import _get_public_key, generate


def test__get_public_key():
    mock_key = mock.MagicMock()
    mock_key.public_key().public_bytes.return_value = "public_key"

    assert _get_public_key(mock_key) == "public_key"


@mock.patch("ownca.crypto.keys._get_public_key")
@mock.patch("ownca.crypto.keys.rsa")
def test_generate(mock_rsa, mock__get_public_key):

    mock__get_public_key.return_value = "public_key"

    mock_key = mock.MagicMock()
    mock_key.__class__ = classmethod
    mock_key.private_bytes.return_value = "private_key"
    mock_key.public_key.return_value = "pem_public_key"

    mock_rsa.generate_private_key.return_value = mock_key

    result = generate()
    assert isinstance(result[0], classmethod)
    assert result[1:] == ("private_key", "pem_public_key", "public_key")
