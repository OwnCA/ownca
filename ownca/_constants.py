#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2018-2020 Kairo de Araujo
"""
import os


# CA directories and files
CA_PRIVATE_DIR = "private"
CA_CERTS_DIR = "certs"
CA_CERT = "ca.crt"
CA_KEY = os.path.join(CA_PRIVATE_DIR, "ca_key.pem")
CA_PUBLIC_KEY = "ca_key.pub"
CA_CRL = "ca.crl"
CA_CSR = "ca.csr"

# Supported OIDS
OIDS = [
    "country_name",
    "locality_name",
    "state_or_province",
    "street_address",
    "organization_name",
    "organization_unit_name",
    "email_address",
]


# Regular Expressions
COUNTRY_REGEX = "^(A(D|E|F|G|I|L|M|N|O|R|S|T|Q|U|W|X|Z)|B(A|B|D|E|F|G|H|I|J|\
                L|M|N|O|R|S|T|V|W|Y|Z)|C(A|C|D|F|G|H|I|K|L|M|N|O|R|U|V|X|Y|Z\
                )|D(E|J|K|M|O|Z)|E(C|E|G|H|R|S|T)|F(I|J|K|M|O|R)|G(A|B|D|E|F\
                |G|H|I|L|M|N|P|Q|R|S|T|U|W|Y)|H(K|M|N|R|T|U)|I(D|E|Q|L|M|N|O\
                |R|S|T)|J(E|M|O|P)|K(E|G|H|I|M|N|P|R|W|Y|Z)|L(A|B|C|I|K|R|S|\
                T|U|V|Y)|M(A|C|D|E|F|G|H|K|L|M|N|O|Q|P|R|S|T|U|V|W|X|Y|Z)|N(\
                A|C|E|F|G|I|L|O|P|R|U|Z)|OM|P(A|E|F|G|H|K|L|M|N|R|S|T|W|Y)|Q\
                A|R(E|O|S|U|W)|S(A|B|C|D|E|G|H|I|J|K|L|M|N|O|R|T|V|Y|Z)|T(C|\
                D|F|G|H|J|K|L|M|N|O|R|T|V|W|Z)|U(A|G|M|S|Y|Z)|V(A|C|E|G|I|N|\
                U)|W(F|S)|Y(E|T)|Z(A|M|W))$"
HOSTNAME_REGEX = "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"
