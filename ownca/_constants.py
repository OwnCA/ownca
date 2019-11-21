#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2018, 2019 Kairo de Araujo
"""

CA_PRIVATE_DIR = f"private"
CA_CERTS_DIR = f"certs"

CA_CERT = f"ca.crt"
CA_KEY = f"{CA_PRIVATE_DIR}/ca_key.pem"
CA_PUBLIC_KEY = f"ca_key.pub"

HOSTNAME_REGEX = "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"
