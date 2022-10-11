#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2018-2020 Kairo de Araujo
"""


class OwnCAInconsistentData(Exception):
    """Certificate file is inconsistent."""

    pass


class OwnCAIntermediate(Exception):
    """CA is a Intermediate Certificate Authority missing certificate file"""
    pass


class OwnCAInvalidFiles(Exception):
    """CA Files are inconsistent."""

    pass


class OwnCAInvalidOID(Exception):
    """Invalid OID"""

    pass


class OwnCAInvalidDataStructure(Exception):
    """Invalid Ownca Data Structure."""

    pass


class OwnCAFatalError(Exception):
    """No controlled Error, fatal error"""

    pass


class OwnCAInvalidCertificate(Exception):
    """The certificate is invalid or not found"""

    pass
