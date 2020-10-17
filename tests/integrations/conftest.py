#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2018-2020 Kairo de Araujo
"""
import os
import shutil


CA_STORAGE = "CA_test"
ICA_STORAGE = "ICA_test"
CA_COMMON_NAME = "ownca.org"
CA_OIDS = {
    "country_name": "BR",
    "locality_name": "Uba",
    "state_or_province": "Minas Gerais",
    "street_address": "Rua Agostinho Martins de Oliveira",
    "organization_name": "First home",
    "organization_unit_name": "Good memories",
    "email_address": "kairo at ...",
}
CA_MAXIMUM_DAYS = 365  # 1 year
CA_DNS_NAMES = ["www.ownca.org", "ca.ownca.org"]


def clean_test(path="CA_test"):
    if os.path.isdir(path):
        shutil.rmtree(path)


def pytest_itemcollected(item):
    par = item.parent.obj
    node = item.obj
    pref = par.__doc__.strip() if par.__doc__ else par.__class__.__name__
    suf = node.__doc__.strip() if node.__doc__ else node.__name__
    if pref or suf:
        item._nodeid = " ".join((pref, suf))
