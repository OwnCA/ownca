#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2018-2020 Kairo de Araujo
"""


def pytest_itemcollected(item):
    par = item.parent.obj
    node = item.obj
    pref = par.__doc__.strip() if par.__doc__ else par.__class__.__name__
    suf = node.__doc__.strip() if node.__doc__ else node.__name__
    if pref or suf:
        item._nodeid = " ".join((pref, suf))
