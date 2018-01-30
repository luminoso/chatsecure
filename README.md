# ChatSecure

ChatSecure was developed at [Aveiro University](https://www.ua.pt) in the course [47232-Security](http://www.ua.pt/ensino/uc/2834) for academic purposes and intents to demonstrate the steps needed in order to have a secure communication channel between two peers and all the inherent aspects to encryption.

This project has the following dependencies:
* [cryptography](https://cryptography.io): ciphers, encryption, decryption, key support, etc
* [PyKCS11](https://bitbucket.org/PyKCS11/pykcs11): PKCS\#11 python interface for smart card
* [PyOpenSSL](http://www.pyopenssl.org): validates certificate chain against a CA Root
* [pem](https://github.com/hynek/pem): parsing and splitting PEM files

It is divided in two phases:

* **M1**: establish a secure communication without authentication
  * Protocol negotiation (AES-128 or AES-256)
  * Session key establishment using RSA asymmetric keys
  * Session channel using symmetric keys (AES, HMAC, etc)
* **M2**: authentication using Portuguese Citizen Card
   * X509 certificate support
   * Certificate chain exchange
   * PCKS\#11 smart card interface for client authentication (Portuguese Citizen ID)
   * Certificate chain validation using [Mozilla's Trusted CAs](https://wiki.mozilla.org/CA:IncludedCAs), including optional revocation checking

This proposal has a client\:server architecture, where the server simply relays the data between two communication peers. It includes two libraries:

* **CSCrypto** has all the needed methods both for clients and server to deal with both for symmetric and asymmetric keys
* **PKCS11_Wrapper** has the abstraction needed to operate with the smart card though the PyKCS11 library

The modules have the following incremental functionality:

#### M1
* CSCrypto
  * Import, export and generate keys
  * Encrypt/Decrypt data
  * Generate/Verify HMAC for encrypted data

#### M2
* CSCrypto
  * Import x509 certificate from PEM format
  * Validate signature against a x509 certificate
  * Validate x509 certificate chain up to the CA root (optional revocation check)
  * Removed base64/pickle dependencies
* PKCS11_Wrapper
  *  Retrieve available certificates from smart card
  *  Retrieve available private keys
  *  Export x509 certificates
  *  Sign using *k* certificate private key available in the smart card


Details about the architecture, protocol used and its implementation are available for in both M1 and M2 reports.


## How to run

ChatSecure is compatible with Linux and MacOS, but probably not with Windows due to [Python *select* limitations on Windows](https://docs.python.org/2/library/select.html).

### M1

1. Install dependencies with with pip:

        $ pip2 install cryptography pykcs11 pyopenssl pem --user
    
2. Launch server

        $ python2 server.py

3. Client Alice:

        $ python2 ChatSecure.py
	    Name:  Alice
        Server cipher sha256 fingerprint is: 5120e699572ccedea43266bab61a196cdd0cec5d8193575f2be5067e94167d82
        Confirm (y/n)? y
        [18:27:32] [Alice-0]  

   Alice is connected and idling.

4. Client Bob communicating to Alice:

        $ python2 ChatSecure.py
        Name:  Bob
        Server cipher sha256 fingerprint is: e98979e3bbb2468b4a3ad003eefef05220532476745e5d68c49e525968b1028f
        Confirm (y/n)? y
        [18:19:00] [Bob-1] help
         
        Available commands are:
        list
        help
        
        Syntax for sending message to 'john':
        john: hello there
        
        [18:19:01] [Bob-1] list
         
        User list:
        1. ID: Alice Level: 0
        2. ID: Bob Level: 0
        
        [18:19:05] [Bob-1] Alice: hello
        [18:19:07] [Bob-1] 

5. Bob and Alice ChatSecure initiates the secure channel and displays the resulting communication at Alice prompt:

        [18:19:06] [Alice-0]  User Bob wants to communicate
        [18:19:07] [Bob]:  hello

### M2

M2 requires a smart card reader and it is designed to be compatible with Portuguese Citizen smart card. The process is the same as M1 but with additions of a few functions:

* **whois** queries the user certificate
* **history** prints the message history and delivery reports

A PKCS\#11 library is also needed, and can be configured at *PKCS11_Wrapper.py* file.

```python
class PKCS11Wrapper:
    __PKCS11_LIB_LINUX = "/usr/local/lib/libpteidpkcs11.so.1.61.0"
    __PKCS11_LIB_DARWIN = "/usr//local/lib/libpteidpkcs11.dylib"
    __CERT_LABEL = "CITIZEN AUTHENTICATION CERTIFICATE"
    __PKCS11_LIB = ""
```

For the Portuguese Citizen Card the required libs are available at https://www.autenticacao.gov.pt

## Limitations

Certificate revocation tests are disabled by default, since the CRLs must be up-to-date and not expired so the validation can pass. To enable uncomment the following lines:

```python
store.set_flags(crypto.X509StoreFlags.CRL_CHECK)
store.set_flags(crypto.X509StoreFlags.CRL_CHECK_ALL)
```

There's a script *refresh_crl.sh* included at M2 folder to mass-update intermediate certificate revocation lists (base and delta) so that *CRL_CHECK* can be enabled.

## Licence

MIT
