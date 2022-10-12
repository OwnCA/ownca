# -*- coding: utf-8 -*-
"""
Copyright (c) 2020 Kairo de Araujo
"""
import pytest
from unittest import mock
from voluptuous import MultipleInvalid
from ownca.exceptions import OwnCAInvalidDataStructure
from ownca.crypto.keys import (
    _validate_owncakeydata,
    _get_public_key,
    OwncaKeyData,
    generate,
)


@mock.patch("ownca.crypto.keys.Schema")
def test__validate_owncakeydata(mock_Schema):

    mocked_schema = mock.MagicMock()
    mocked_schema.return_value = None
    mock_Schema.return_value = mocked_schema

    assert (
        _validate_owncakeydata(
            {
                "key": "key",
                "key_bytes": "key_bytes",
                "public_key": "public_key",
                "public_key_bytes": "public_key_bytes",
            }
        )
        is None
    )


@mock.patch("ownca.crypto.keys.Schema")
def test__validate_owncakeydata_exception(mock_Schema):

    mocked_schema = mock.MagicMock()
    mocked_schema.side_effect = MultipleInvalid("x")
    mock_Schema.return_value = mocked_schema

    with pytest.raises(OwnCAInvalidDataStructure) as err:
        _validate_owncakeydata(
            {
                "key": "key",
                "key_bytes": "key_bytes",
                "public_key": "public_key",
                "public_key_bytes": "public_key_bytes",
            }
        )

        assert "OwncaKeyData: " in err.value


@mock.patch("ownca.crypto.keys._validate_owncakeydata")
def test_owncakeydata(mock__validate_owncakeydata):

    mock__validate_owncakeydata.return_value = None
    result = OwncaKeyData(
        {
            "key": "key",
            "key_bytes": "key_bytes",
            "public_key": "public_key",
            "public_key_bytes": "public_key_bytes",
        }
    )

    assert isinstance(result, OwncaKeyData)
    assert result.key == "key"
    assert result.key_bytes == "key_bytes"
    assert result.public_key == "public_key"
    assert result.public_key_bytes == "public_key_bytes"


@mock.patch("ownca.crypto.keys._validate_owncakeydata")
def test_owncakeydata_exception(mock__validate_owncakeydata):

    mock__validate_owncakeydata.side_effect = OwnCAInvalidDataStructure

    with pytest.raises(OwnCAInvalidDataStructure) as err:
        OwncaKeyData(
            {
                "key": "key",
                "key_bytes": "key_bytes",
                "public_key": "public_key",
                "public_key_bytes": "public_key_bytes",
            }
        )

        assert "OwncaKeyData:" in err.value


def test__get_public_key():
    mock_key = mock.MagicMock()
    mock_key.public_key().public_bytes.return_value = "public_key"

    assert _get_public_key(mock_key) == "public_key"


@mock.patch("ownca.crypto.keys._validate_owncakeydata")
@mock.patch("ownca.crypto.keys._get_public_key")
@mock.patch("ownca.crypto.keys.rsa")
def test_generate(mock_rsa, mock__get_public_key, mock_validate__owncakeydata):

    mock__get_public_key.return_value = "public_key_bytes"
    mock_validate__owncakeydata.return_value = None
    mock_key = mock.MagicMock()
    mock_key.__class__ = classmethod
    mock_key.private_bytes.return_value = "private_key"
    mock_key.public_key.return_value = "public_key"

    mock_rsa.generate_private_key.return_value = mock_key

    result = generate()
    assert isinstance(result.key, classmethod)
    assert result.key_bytes == "private_key"
    assert result.public_key == "public_key"
    assert result.public_key_bytes == "public_key_bytes"
