# -*- coding: utf-8 -*-
# Version 2.0

import os
import pickle
from hashlib import sha256
from os import listdir
from os.path import isfile, join

from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as _aspaadding
from cryptography.hazmat.primitives.asymmetric import rsa, AsymmetricVerificationContext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pem import parse_file

RANDOM_ENTROPY_GENERATOR_SIZE = 32


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


def csc_pickle_asymEnc(aPubKey, data):
    """
    Pickle dumps the data, performs asymmetric encryption and encodes the result in base64
    :param aPubKey: public asymmetric cipher to use
    :type aPubKey: cryptography.hazmat.primitives.ciphers.RSAPublicKey
    :param data: to pickle dump, encrypt and b64 encode
    :return: computed encrypted and pickled data
    :rtype: bytearray
    """
    pickle_dumps = pickle.dumps(data)
    return aPubKey.encrypt(pickle_dumps,
                           _aspaadding.OAEP(
                               mgf=_aspaadding.MGF1(algorithm=hashes.SHA256()),
                               algorithm=hashes.SHA256(),
                               label=None)
                           )


def csc_asymDec_unpickle(aPriKey, data):
    """
    Base 64 decodes the data, decrypt with private asymmetric cipher and pickle loads
    :param aPriKey: private asymmetric cipher to use
    :type aPriKey: cryptography.hazmat.primitives.ciphers.RSAPrivateKey
    :param data: to b64 decode, decrypt and pickle loads
    :return: native python object
    """

    cleartext_data = aPriKey.decrypt(data, _aspaadding.OAEP(
        mgf=_aspaadding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    return pickle.loads(cleartext_data)


def csc_get_aPubKey_from_pem(pem):
    """
    Generate asymmetric cipher from pem
    :param pem text
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


def csc_aPrivate_sign(aPrivKey, data):
    # type: (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey, str) -> str
    """
    Signs the data with an private key.
    :param aPrivKey: private key to use
    :param data: to sign
    :return: signed bytes
    """
    return aPrivKey.sign(data,
                         _aspaadding.PSS(
                             mgf=_aspaadding.MGF1(hashes.SHA256()),
                             salt_length=_aspaadding.PSS.MAX_LENGTH),
                         hashes.SHA256()
                         )


def csc_aPublic_validate_signature(data, sign_bytes, public_pem):
    """
    Validates if the data sign_bytes was signed using the public key
    :param data: signed
    :param sign_bytes: bytes of the signature produced
    :param public_pem: public key to verify if the signature is correct
    :return: None if everything Ok
    """
    # type: (str, str, str) -> None

    cipher = csc_get_aPubKey_from_pem(public_pem)

    # Generate an verification context from the given public key and signature
    verifier = cipher.verifier(
        sign_bytes,
        _aspaadding.PSS(
            mgf=_aspaadding.MGF1(hashes.SHA256()),
            salt_length=_aspaadding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )  # type: AsymmetricVerificationContext

    # Validates if the signature was performed using the given certificate and message
    verifier.update(data)
    return verifier.verify()


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


def csc_symDec_unpickle(cipher, key, hmac, data):
    """
    Base 64 decodes the data, decrypt with symmetric cipher and pickle loads.
    This includes the unpadding process.
    :param hmac: HMAC bytes
    :param cipher: cipher cipher to use to decode
    :type cipher: cryptography.hazmat.primitives.ciphers.Cipher
    :param key: key to use in HMAC validation
    :type key: bytearray
    :param data: to decrypt, unpad and pickle loads
    :return: the python object
    """
    key = sha256(key).hexdigest()
    csc_HMAC_update_verify(key, hmac, data)
    decryptor = cipher.decryptor()
    deciphered_padded = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    cleartext_data = unpadder.update(deciphered_padded) + unpadder.finalize()
    data, random = pickle.loads(cleartext_data)
    return data


def csc_pickle_symEnc(cipher, key, data):
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
    pickle_dumps = pickle.dumps([data, os.urandom(RANDOM_ENTROPY_GENERATOR_SIZE)])
    padder = padding.PKCS7(128).padder()
    cleartext_data_padded = padder.update(pickle_dumps) + padder.finalize()
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(cleartext_data_padded) + encryptor.finalize()
    key = sha256(key).hexdigest()
    hmac_data = csc_HMAC_update_finalize(key, encrypted_data)
    return [encrypted_data, hmac_data]


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


def csc_derive_key(masterkey, random=os.urandom(16)):
    """
    Derives a key from the given master key and random
    :param masterkey: Original key to derive
    :param random; random to use
    :return: The derived key and the random used
    """

    # Key Derivation Function
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=random,
        iterations=100000,
        backend=default_backend()
    )

    # Derives the key using the generated random
    return kdf.derive(masterkey), random


#
# x509 Certificate functions
#


def csc_generate_x509_cryptography_io_from_pem(cert_pem):
    # type: (str) -> x509.Certificate
    """
    Generates an x509 from serialized certificate in PEM format
    :param cert_pem: serialized certificate
    :return: x509 cryptography.io object
    """
    return x509.load_pem_x509_certificate(cert_pem, default_backend())


def csc_validate_x509_signature(message, sign_bytes, x509_pem):
    # type: (str, str, str) -> None
    """
    Validates an message and its signature according to a given certificate
    :param message: that was signed
    :param sign_bytes: result signature bytes
    :param x509_pem: certificate used to sign the message
    :return: None if everything Ok, Exception if not
    """

    cert = x509.load_pem_x509_certificate(x509_pem, default_backend())
    # Extract public key from certificate
    sign_cert_pk = cert.public_key()  # type: rsa.RSAPublicKey

    # Generate an verification context from the given public key and signature
    verifier = sign_cert_pk.verifier(
        sign_bytes,
        _aspaadding.PKCS1v15(),
        hashes.SHA256()
    )  # type: AsymmetricVerificationContext

    # Validates if the signature was performed using the given certificate and message
    verifier.update(message)
    return verifier.verify()


def csc_validate_chain(chain, pem_certificate, ssl_ca_root_file="./mozilla-ca-bundle.txt"):
    # type: (list, str, str) -> None
    """
    Validates an chain up to CA root, including if the certificate is revoked.
    This solves the graph from the given certificates against a list of trusted CA certificates.
    :param chain:  to validate (CA root excluded)
    :param pem_certificate: to validate in the chain
    :param ssl_ca_root_file: optional file containing CA roots
    :return: None if everything ok
    """

    # parse CA roots certificate PEMs to an list
    trusted_certs_pems = parse_file(ssl_ca_root_file)

    # create a new store
    store = crypto.X509Store()

    # check middle CAs for revocation
    #store.set_flags(crypto.X509StoreFlags.CRL_CHECK)

    # check just the certificate CRL and not if all certificates up to the root are revoked
    # not recommended since requires all CAs root revogations
    #store.set_flags(crypto.X509StoreFlags.CRL_CHECK_ALL)

    # add system trusted CA roots to store
    for pem in trusted_certs_pems:
        store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, str(pem)))

    # load supplied chain
    for pem in chain:
        store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, str(pem)))

    # convert pem to OpenSSL certificate format
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, pem_certificate)

    # validate full chain
    store_ctx = crypto.X509StoreContext(store, certificate)

    # load CRLs to the store
    for crl in [f for f in listdir("CRL") if isfile(join("CRL", f))]:
        store.add_crl(crypto.load_crl(crypto.FILETYPE_ASN1, open(join("CRL", crl), "r").read()))

    store_ctx.verify_certificate()


def csc_pretty_cert_text(pem):
    # type: (str) -> str
    """
    Prints in a pretty way the certificate data
    :param pem: of the certificate
    """
    c = csc_generate_x509_cryptography_io_from_pem(pem)
    dados = \
        {
            u'Nome': c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
            u'Pais': c.issuer.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value,
            u'Organização': c.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value,
            u'Instituicao': c.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value,
            u'Identificação': c.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)[0].value,
            u'Válido de': str(c.not_valid_before),
            u'Válido até': str(c.not_valid_after)
        }

    output = ""
    for i in dados:
        output += u'{0:14} : {1:<10}\n'.format(i, dados[i])

    return output


class CScrypto:
    __trusted_certs_pems = []

    def __init__(self, file="./ca-bundle.crt"):
        self.__trusted_certs_pems = parse_file(file)

    def getpems(self):
        return self.__trusted_certs_pems
