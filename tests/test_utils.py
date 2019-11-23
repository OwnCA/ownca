#
# Copyright (c) 2019 Kairo de Araujo
#
from ownca.utils import validate_hostname


def test_validate_hostname():

    assert validate_hostname("myserver")
    assert validate_hostname("myserver.com")
