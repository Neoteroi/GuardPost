import json
import os

import pytest

from guardpost.errors import UnsupportedFeatureError
from guardpost.jwks import JWK, JWKS, KeyType


def _get_ec_jwks_dict():
    path = os.path.join(os.path.dirname(__file__), "res", "ec_jwks.json")
    with open(path, encoding="utf8") as f:
        return json.load(f)


def test_keytype_from_str():
    assert KeyType.from_str("EC") is KeyType.EC
    assert KeyType.from_str("oct") is KeyType.OCT
    assert KeyType.from_str("RSA") is KeyType.RSA
    assert KeyType.from_str("OKP") is KeyType.OKP

    with pytest.raises(ValueError):
        KeyType.from_str("xx")

    with pytest.raises(ValueError):
        KeyType.from_str("")


def test_jwks_raises_for_missing_keys():
    with pytest.raises(ValueError):
        JWKS.from_dict({})


def test_jwk_raises_for_unsupported_type():
    with pytest.raises(UnsupportedFeatureError):
        JWK.from_dict({"kty": "oct"})

    with pytest.raises(ValueError):
        JWK.from_dict({"kty": "RSA"})


def test_jwks_update():
    jwks_1 = JWKS.from_dict(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "0",
                    "n": "xzO7x0gEMbktuu5RLUqiABJNqt4kdm_5ucsKgSdHUdUcbkG28dLAikoFTki9awmyapSbO84zlKMaH24obOe44hd32sdeMOdQp0TxpxE95HfYVFuAWdfCM4Bz_x32Sq51e7x6oZd09vODFFbwTlMJ27LPAEuI5G6UVQKxhIB_wA2FOPkbHeDncB7jYv9kLidvpNgp5PC-aKHKv9ay6gi7M-wUQEpeQMjpyDFN2p_q12BWSUbsRwOjhYtCuSmmBNh07MizzVIQjpmZU5f6qmZHw--iJSBD52wsI87itYbBwRcDN5ffColkFpA8va0hDlShI2qVmwtQ3LUpZVivKuJOSw==",
                    "e": "AQAB",
                },
                {
                    "kty": "RSA",
                    "kid": "1",
                    "n": "3a-KHqLSxXba1e-qa2cWaV6VNd3LsNptZsbd1eZj402lehEbHm8ZdjHlZNwirPeqhvHYbCGRKfqLV2jE1UacfkCmcP8u7klENFbl01IyA8-MiVfmRB6BWlaBNS0NCDIGJ1GY7aPfEOJgGc5L4laIAD6iSVTfUwNtkLVAHXx5OQjJIVIxk6Vkji1n2JvpEO9337Kp96-AqfpIFWyCLg56uGJfK6XdlDYZvPm17xorcLGUB9MBsOID7PbdqeVnmaKW9aFNZj1OaDTZAsNqnxGkmsp3wkds8Th3raIbYvotQEGm1BCdEbqj3hu05bIEZuQbWuNTIseYCKFw7GJXawEKzQ==",
                    "e": "AQAB",
                },
            ]
        }
    )

    jwks_2 = JWKS.from_dict(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "2",
                    "n": "nk4LTnUzUBqmQTdMmNaHRU6FHHHXfW7TwOoVnCSu36PKyFovRGs5Qiec1VBmF4PZCXlkAwmpBPf4iBbWr3xXU4lE8d3OBuqnf-qFWbOCkyNFp_kyqHu7SlGHJhYilfRzKqDGJ5FqIafBpXID_FsxTqNi-mf98G_jm_QoF5ifMAPUf0eVTCjzs9fcawnKDbeaAED3SbYJt-EVjdcOJalilXJWPNdpGx8ouF1Zn77NDEbj6_1BBk22AZI1yQzDy8c08HlEK1NQgToJyQ-CLP6deHYiHrxMSZe83WbkCvxr1PLMFZlUTWh2AcgbiR9zJARu7nk6PWTbBhreuXRL5meGMQ==",
                    "e": "AQAB",
                },
                {
                    "kty": "RSA",
                    "kid": "3",
                    "n": "v_6KlxHChgEdhvV5t6cDi2h-u2y355dxkwIp1YM4YINXKNStSnFUTkRIPXAY9H15kn6CuWCSWXl7jRwCPm5UOBnC9TjKJTuTK_IVJrTqd1dFkxOEsesKKBPsc0nBjtYMc0c_74K0OxJphy6I4d0M6gXWVOx1avOMEU7LQHE18WtfSYXtBk_Q51foM8StqFARCKAdyRZRXwhtS71lPrHNLhU2aayKBKpWL-r-q4KZGwDLtw0z3bHR5Z_bIJVGushkYLN_DaJvkvypb1y7Lq6ozMovLA5xHgYhv6VCUGWOAJWo9PZXjtwjrO8gXME-msBmB7iO-ltV0FM3O9wTqsJJxw==",
                    "e": "AQAB",
                },
            ]
        }
    )

    jwks_1.update(jwks_2)

    assert len(jwks_1.keys) == 4

    assert [key.kid for key in jwks_1.keys] == "0 1 2 3".split()


def test_jwks_update_override():
    jwks_1 = JWKS.from_dict(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "0",
                    "n": "xzO7x0gEMbktuu5RLUqiABJNqt4kdm_5ucsKgSdHUdUcbkG28dLAikoFTki9awmyapSbO84zlKMaH24obOe44hd32sdeMOdQp0TxpxE95HfYVFuAWdfCM4Bz_x32Sq51e7x6oZd09vODFFbwTlMJ27LPAEuI5G6UVQKxhIB_wA2FOPkbHeDncB7jYv9kLidvpNgp5PC-aKHKv9ay6gi7M-wUQEpeQMjpyDFN2p_q12BWSUbsRwOjhYtCuSmmBNh07MizzVIQjpmZU5f6qmZHw--iJSBD52wsI87itYbBwRcDN5ffColkFpA8va0hDlShI2qVmwtQ3LUpZVivKuJOSw==",
                    "e": "AQAB",
                },
                {
                    "kty": "RSA",
                    "kid": "1",
                    "n": "3a-KHqLSxXba1e-qa2cWaV6VNd3LsNptZsbd1eZj402lehEbHm8ZdjHlZNwirPeqhvHYbCGRKfqLV2jE1UacfkCmcP8u7klENFbl01IyA8-MiVfmRB6BWlaBNS0NCDIGJ1GY7aPfEOJgGc5L4laIAD6iSVTfUwNtkLVAHXx5OQjJIVIxk6Vkji1n2JvpEO9337Kp96-AqfpIFWyCLg56uGJfK6XdlDYZvPm17xorcLGUB9MBsOID7PbdqeVnmaKW9aFNZj1OaDTZAsNqnxGkmsp3wkds8Th3raIbYvotQEGm1BCdEbqj3hu05bIEZuQbWuNTIseYCKFw7GJXawEKzQ==",
                    "e": "AQAB",
                },
            ]
        }
    )

    jwks_2 = JWKS.from_dict(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "0",
                    "n": "nk4LTnUzUBqmQTdMmNaHRU6FHHHXfW7TwOoVnCSu36PKyFovRGs5Qiec1VBmF4PZCXlkAwmpBPf4iBbWr3xXU4lE8d3OBuqnf-qFWbOCkyNFp_kyqHu7SlGHJhYilfRzKqDGJ5FqIafBpXID_FsxTqNi-mf98G_jm_QoF5ifMAPUf0eVTCjzs9fcawnKDbeaAED3SbYJt-EVjdcOJalilXJWPNdpGx8ouF1Zn77NDEbj6_1BBk22AZI1yQzDy8c08HlEK1NQgToJyQ-CLP6deHYiHrxMSZe83WbkCvxr1PLMFZlUTWh2AcgbiR9zJARu7nk6PWTbBhreuXRL5meGMQ==",
                    "e": "AQAB",
                },
                {
                    "kty": "RSA",
                    "kid": "3",
                    "n": "v_6KlxHChgEdhvV5t6cDi2h-u2y355dxkwIp1YM4YINXKNStSnFUTkRIPXAY9H15kn6CuWCSWXl7jRwCPm5UOBnC9TjKJTuTK_IVJrTqd1dFkxOEsesKKBPsc0nBjtYMc0c_74K0OxJphy6I4d0M6gXWVOx1avOMEU7LQHE18WtfSYXtBk_Q51foM8StqFARCKAdyRZRXwhtS71lPrHNLhU2aayKBKpWL-r-q4KZGwDLtw0z3bHR5Z_bIJVGushkYLN_DaJvkvypb1y7Lq6ozMovLA5xHgYhv6VCUGWOAJWo9PZXjtwjrO8gXME-msBmB7iO-ltV0FM3O9wTqsJJxw==",
                    "e": "AQAB",
                },
            ]
        }
    )

    jwks_1.update(jwks_2)

    assert len(jwks_1.keys) == 3

    key_0 = next((key for key in jwks_1.keys if key.kid == "0"), None)
    assert key_0 is not None
    assert key_0.n == jwks_2.keys[0].n


def test_jwk_ec_p256_from_dict():
    ec_jwks = _get_ec_jwks_dict()
    key_data = next(k for k in ec_jwks["keys"] if k["kid"] == "ec256")
    jwk = JWK.from_dict(key_data)
    assert jwk.kty is KeyType.EC
    assert jwk.crv == "P-256"
    assert jwk.x == key_data["x"]
    assert jwk.y == key_data["y"]
    assert jwk.kid == "ec256"
    assert jwk.pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert jwk.n is None
    assert jwk.e is None


def test_jwk_ec_p384_from_dict():
    ec_jwks = _get_ec_jwks_dict()
    key_data = next(k for k in ec_jwks["keys"] if k["kid"] == "ec384")
    jwk = JWK.from_dict(key_data)
    assert jwk.kty is KeyType.EC
    assert jwk.crv == "P-384"
    assert jwk.pem.startswith(b"-----BEGIN PUBLIC KEY-----")


def test_jwk_ec_p521_from_dict():
    ec_jwks = _get_ec_jwks_dict()
    key_data = next(k for k in ec_jwks["keys"] if k["kid"] == "ec521")
    jwk = JWK.from_dict(key_data)
    assert jwk.kty is KeyType.EC
    assert jwk.crv == "P-521"
    assert jwk.pem.startswith(b"-----BEGIN PUBLIC KEY-----")


def test_jwk_ec_raises_for_unsupported_curve():
    with pytest.raises(ValueError, match="Unsupported EC curve"):
        JWK.from_dict({"kty": "EC", "crv": "P-192", "x": "abc", "y": "def"})


def test_jwk_ec_raises_for_missing_fields():
    with pytest.raises(ValueError, match="Missing crv"):
        JWK.from_dict({"kty": "EC", "x": "abc", "y": "def"})

    with pytest.raises(ValueError, match="Missing x"):
        JWK.from_dict({"kty": "EC", "crv": "P-256", "y": "def"})

    with pytest.raises(ValueError, match="Missing y"):
        JWK.from_dict({"kty": "EC", "crv": "P-256", "x": "abc"})


def test_jwks_from_dict_with_ec_keys():
    ec_jwks = _get_ec_jwks_dict()
    jwks = JWKS.from_dict(ec_jwks)
    assert len(jwks.keys) == 3
    kids = {k.kid for k in jwks.keys}
    assert kids == {"ec256", "ec384", "ec521"}
    for key in jwks.keys:
        assert key.kty is KeyType.EC
        assert key.pem is not None
