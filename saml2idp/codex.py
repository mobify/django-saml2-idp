# Portions borrowed from:
# http://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations
import zlib
import base64

from django.utils.six import binary_type


def decode_base64_and_inflate(b64string):
    decoded_data = base64.b64decode(b64string)
    return zlib.decompress(decoded_data, -15)


def deflate_and_base64_encode(string_val):
    zlibbed_str = zlib.compress(string_val.encode('utf8'))
    compressed_string = zlibbed_str[2:-4]
    return base64.b64encode(compressed_string)


def nice64(src):
    """ Returns src base64-encoded and formatted nicely for our XML. """
    assert isinstance(src, binary_type), 'Can only encode bytes'
    return base64.b64encode(src).decode('ascii')
