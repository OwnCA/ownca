#
# Copyright (c) 2019 Kairo de Araujo
#
from ownca.utils import file_data_status, validate_hostname


def test_file_data_status():
    ca_status = {
        "key": True,
        "certificate": True
    }
    assert file_data_status(ca_status)


def test_validate_hostname():

    assert validate_hostname("myserver")
    assert validate_hostname("myserver.com")


def test_validate_hostname_invalid_type():

    assert validate_hostname(1) is False
    assert validate_hostname(True) is False
    assert validate_hostname(0.1) is False


def test_validate_hostname_invalid_size():

    assert validate_hostname("a"*250 + " .com") is False


def test_validate_hostname_invalid_string_chars():

    assert validate_hostname("#*#($#$&(") is False
