# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, unicode_literals

import structlog


def get_saml_logger():
    """
    Get a logger named `saml2idp` after the main package.
    """
    return structlog.get_logger('saml2idp')
