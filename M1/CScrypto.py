# encoding: utf-8
# Version 1.0

import base64
import pickle
from hashlib import sha256

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as _aspaadding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# This library includes operations for symmetric and asymmetric key operations, heavily supported on
# cryptography.io library.
#
# Functions include both for symmetric and asymmetric keys
# * load/save key from file/base64 format
# * cipher/decipher data
# * generate new keys
# * HMAC generation/validation

#
# ASYMMETRIC KEYS FUNCTIONS
#

def csc_generate_aPrivKey():
    """
    Generates an RSA Private cipher
    :return: RSA private cipher
    :rtype: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


def csc_load_aPrivKey_from_file(filename, password=None):
    """
    Loads a cipher from a file
    :param filename: to load
    :type filename: str
    :param password password to open the private cipher
    :return: RSA private cipher
    :rtype: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
    """
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
            backend=default_backend()
        )
    return private_key


def csc_pickle_asymEnc_b64enc(aPubKey, data):
    """
    Pickle dumps the data, performs asymmetric encryption and encodes the result in base64
    :param aPubKey: public asymmetric cipher to use
    :type aPubKey: cryptography.hazmat.primitives.ciphers.RSAPublicKey
    :param data: to pickle dump, encrypt and b64 encode
    :return: computed string
    :rtype: str
    """
    pickle_dumps = pickle.dumps(data)
    encrypted_data = aPubKey.encrypt(pickle_dumps,
                                     _aspaadding.OAEP(
                                         mgf=_aspaadding.MGF1(algorithm=hashes.SHA256()),
                                         algorithm=hashes.SHA256(),
                                         label=None)
                                     )
    return base64.b64encode(encrypted_data)


def csc_b64dec_asymDec_pickle(aPriKey, data):
    """
    Base 64 decodes the data, decrypt with private asymmetric cipher and pickle loads
    :param aPriKey: private asymmetric cipher to use
    :type aPriKey: cryptography.hazmat.primitives.ciphers.RSAPrivateKey
    :param data: to b64 decode, decrypt and pickle loads
    :return: native python object
    """
    base64_decoded = base64.b64decode(data)
    cleartext_data = aPriKey.decrypt(base64_decoded, _aspaadding.OAEP(
        mgf=_aspaadding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    return pickle.loads(cleartext_data)


def csc_get_aPubKey_from_pem(pem):
    """
    Generate asymmetric cipher from pem
    :param pem tex
    :return: RSA public cipher
    :rtype: cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey
    """
    return serialization.load_pem_public_key(pem, backend=default_backend())


def csc_get_pem_from_aPriKey(aPriKey):
    """
    Generates the public bytes of the private asymmetric cipher
    :param aPriKey: asymmetric private cipher to use to export the public pem
    :type aPriKey: cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey
    :return: string pem format of the public cipher
    :rtype: str
    """
    return aPriKey.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)


#
# SYMMETRIC KEYS FUNCTIONS
#

def csc_generate_symKey(password, iv):
    """
    Uses the given password and iv to generate a cipher
    :param password: to use (password)
    :param iv: to use
    :return: generated cipher
    :rtype : cryptography.hazmat.primitives.ciphers.Cipher
    """
    return Cipher(algorithms.AES(password), modes.CBC(iv), backend=default_backend())


def csc_b64dec_symDec_pickle(cipher, key, hmac64enc, data):
    """
    Base 64 decodes the data, decrypt with symmetric cipher and pickle loads.
    This includes the unpadding process.
    :param hmac64enc: HMAC encoded in base64
    :param cipher: cipher cipher to use to decode
    :type cipher: cryptography.hazmat.primitives.ciphers.Cipher
    :param key: key to use in HMAC validation
    :type key: bytearray
    :param data: to b64 decode, unecrypt, unpad and pickle load
    :return: the python object
    """
    base64_decoded = base64.b64decode(data)
    key = sha256(key).hexdigest()
    csc_HMAC_update_verify(key, base64.b64decode(hmac64enc), base64_decoded)
    decryptor = cipher.decryptor()
    deciphered_padded = decryptor.update(base64_decoded) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    cleartext_data = unpadder.update(deciphered_padded) + unpadder.finalize()
    return pickle.loads(cleartext_data)


def csc_pickle_symEnc_b64enc(cipher, key, data):
    """
    Pickle dumps an object, pads, encrypts and base64 encodes
    :param cipher: symmetric cipher to use
    :type cipher: cryptography.hazmat.primitives.ciphers.Cipher
    :param key: key to use in HMAC validation
    :type key: bytearray
    :param data: object to pickle dump, encrypt and base64 encode
    :return: List with [encrypted data, hmac data]
    :rtype: list
    """
    pickle_dumps = pickle.dumps(data)
    padder = padding.PKCS7(128).padder()
    cleartext_data_padded = padder.update(pickle_dumps) + padder.finalize()
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(cleartext_data_padded) + encryptor.finalize()
    key = sha256(key).hexdigest()
    hmacdata = csc_HMAC_update_finalize(key, encrypted_data)
    return [base64.b64encode(encrypted_data), base64.b64encode(hmacdata)]


def csc_HMAC_update_finalize(key, data):
    """
    Generates HMAC byte array with a key for a given data
    :param key: to use to generate the HMAC
    :param data: byte array with the data to generate HMAC
    :return: byte array with HMAC for the given data
    :rtype: bytearray
    """
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()


def csc_HMAC_update_verify(key, hmacdata, data):
    """
    Verifies the integrity of the data with the given hmac data
    :param key: to use for the HMAC
    :param hmacdata: to use
    :param data: to verify
    :return: None
    """
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.verify(hmacdata)
