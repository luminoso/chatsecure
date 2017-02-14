import logging
import sys
from platform import os

import PyKCS11
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding

# PyCKS11 homepage: https://bitbucket.org/PyKCS11/pykcs11/overview
# PyCKS11 documentation: http://pkcs11wrap.sourceforge.net/api/

log = logging.getLogger("Wrapper")


class PKCS11Wrapper:
    __PKCS11_LIB_LINUX = "/usr/local/lib/libpteidpkcs11.so.1.61.0"
    __PKCS11_LIB_DARWIN = "/usr//local/lib/libpteidpkcs11.dylib"
    __CERT_LABEL = "CITIZEN AUTHENTICATION CERTIFICATE"
    __PKCS11_LIB = ""
    __session = None  # type: PyKCS11.Session

    def __init__(self, debug=False):
        # type: () -> PKCS11Wrapper

        if debug:
            logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                                formatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        if os.uname()[0] == "Darwin":
            if os.path.isfile(self.__PKCS11_LIB_DARWIN):
                self.__PKCS11_LIB = self.__PKCS11_LIB_DARWIN
            else:
                logging.error("PKCS11 library " + self.__PKCS11_LIB_DARWIN + " doesn't exist!")
                raise
        else:
            if os.path.isfile(self.__PKCS11_LIB_LINUX):
                self.__PKCS11_LIB = self.__PKCS11_LIB_LINUX
            else:
                logging.error("PKCS11 library " + self.__PKCS11_LIB_LINUX + " doesn't exist!")
                raise

        log.info("Selected lib: %s", self.__PKCS11_LIB)

    def __get_pkcs11_session(self):
        # type: () -> Union[None, Session]

        pkcs11 = PyKCS11.PyKCS11Lib()

        if self.__session is None:
            try:
                pkcs11.load(self.__PKCS11_LIB)
                slots = pkcs11.getSlotList()
            except PyKCS11.PyKCS11Error:
                log.exception("Couldn't load lib and get slot list")
                raise

            try:
                self.__session = pkcs11.openSession(slots[0])
                return self.__session
            except (IndexError, PyKCS11.PyKCS11Error):
                log.debug("Card reader not detected, inserted or locked")
                raise
        else:
            return self.__session

    def smart_card_detected(self):
        """
        Checks if there's a card reader and card.
        :return:
        """

        session = self.__get_pkcs11_session()

        return False if session is None else True

    def get_available_certs_as_list(self):

        session = self.__get_pkcs11_session()

        if session is not None:
            cert = session.findObjects(template=([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]))

            return [c.to_dict()['CKA_LABEL'] for c in cert]

        return []

    def get_available_keys_as_list(self):

        session = self.__get_pkcs11_session()

        if session is not None:
            cert = session.findObjects(template=([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)]))

            return [c.to_dict()['CKA_LABEL'] for c in cert]

        return []

    def get_certificate_pem(self, label="CITIZEN AUTHENTICATION CERTIFICATE"):
        # type: (str) -> str

        session = self.__get_pkcs11_session()

        if session is not None:
            try:
                objs = session.findObjects(template=[(PyKCS11.CKA_LABEL, label),
                                                     (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]
                                           )

            except PyKCS11.PyKCS11Error:
                log.exception("Couldn't get certificate from smart card")
                raise

            try:
                der = ''.join(chr(c) for c in objs[0].to_dict()['CKA_VALUE'])
            except (IndexError, TypeError):
                log.exception("Certificate " + label + " not found.")
                raise

            return x509.load_der_x509_certificate(der, default_backend()).public_bytes(Encoding.PEM)

    def sign(self, data, label="CITIZEN AUTHENTICATION KEY"):
        # type: (any, str) -> str

        session = self.__get_pkcs11_session()

        if session is not None:
            try:
                key = session.findObjects(
                    template=[(PyKCS11.CKA_LABEL, label),
                              (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                              (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA)]
                )[0]

                mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, "")

                ckbytelist = session.sign(key, data, mech)
                """:type ckbytelist: ckbytelistSignature"""

            except PyKCS11.PyKCS11Error:
                log.exception("Couldn't sign message")
                raise
            except IndexError:
                log.exception("Key " + label + " not found")
                raise

            return ''.join(chr(c) for c in ckbytelist)
