# -*- coding: utf-8 -*-
#
# jpbarraca@ua.pt
# jmr@ua.pt 2016

# vim settings:
# :set expandtab ts=4

import logging
import random
import sys
import time
from select import select
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR

from CSaux import Connection, Communications
from CScrypto import *

HOST = ""  # All available interfaces
PORT = 8080  # The server port

SUPPORTED_CIPHERS = ["RSA_NONE_AES128_CBC_HMAC", "RSA_NONE_AES256_CBC_HMAC"]


class Server(Communications):
    def __init__(self, host, port):
        self.ss = socket(AF_INET, SOCK_STREAM)  # the server socket (IP \ TCP)
        self.ss.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.ss.bind((host, port))
        self.ss.listen(10)
        logging.info("Secure IM server listening on %s", self.ss.getsockname())
        # clients to manage (indexed by socket and by name):
        self.connections = {}  # clients (cipher is socket)
        self.id2client = {}  # clients (cipher is id)

        # not needed anymore. we generate a new RSA key for earch user connection
        # self.akey = csc_load_aPrivKey_from_file("priv.key")
        # """:type akey: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey"""

    def stop(self):
        """ Stops the server closing all sockets
        """
        logging.info("Stopping Server")
        try:
            self.ss.close()
        except:
            logging.exception("Server.stop")

        for csock in self.connections:
            try:
                self.connections[csock].close()  # Client.close!
            except:
                # this should not happen since close is protected...
                logging.exception("clients[csock].close")

        # If we delClient instead, the following would be unnecessary...
        self.connections.clear()
        self.id2client.clear()

    def addClient(self, csock, addr):
        """Add a client connecting in csock."""
        if csock in self.connections:
            logging.error("Client NOT Added: %s already exists", self.connections[csock])
            return

        client = Connection(csock, addr)
        self.connections[client.socket] = client
        logging.info("Client added: %s", client)

    def delClient(self, csock):
        """Delete a client connected in csock."""
        if csock not in self.connections:
            logging.error("Client NOT deleted: %s not found", self.connections[csock])
            return

        client = self.connections[csock]
        assert client.socket == csock, "client.socket (%s) should match cipher (%s)" % (client.socket, csock)

        client.socket.send("Client name already exists, exiting...")

        if client.id in self.id2client.keys():
            del self.id2client[client.id]

        del self.connections[client.socket]
        client.close()
        logging.info("Client deleted: %s", client)

    def accept(self):
        """Accept a new connection.
        """
        try:
            csock, addr = self.ss.accept()
            self.addClient(csock, addr)
        except:
            logging.exception("Could not accept client")

    def loop(self):
        while True:
            # sockets to select for reading: (the server socket + every open client connection)
            rlist = [self.ss] + self.connections.keys()
            # sockets to select for writing: (those that have something in bufout)
            wlist = [sock for sock in self.connections if len(self.connections[sock].bufout) > 0]
            logging.debug("select waiting for %dR %dW %dX", len(rlist), len(wlist), len(rlist))
            (rl, wl, xl) = select(rlist, wlist, rlist)
            logging.debug("select: %s %s %s", rl, wl, xl)

            # Deal with incoming data:
            for s in rl:
                if s is self.ss:
                    self.accept()
                elif s in self.connections:
                    self.flushin(s)
                else:
                    logging.error("Incoming, but %s not in clients anymore", s)

            # Deal with outgoing data:
            for s in wl:
                if s in self.connections:
                    self.flushout(s)
                else:
                    logging.error("Outgoing, but %s not in clients anymore", s)

            for s in xl:
                logging.error("EXCEPTION in %s. Closing", s)
                self.delClient(s)

    def clientList(self):
        """
        Return the client list
        """
        cl = []
        for k in self.connections:
            cl.append(self.connections[k].asDict())

        return cl

    def processConnect(self, sender, request):
        """
        Process a connect message from a client
        """
        if sender.state == Connection.STATE_CONNECTED:
            logging.warning("Client is already connected: %s" % sender)
            return

        if not all(k in request.keys() for k in ("name", "ciphers", "phase", "id")):
            logging.warning("Connect message with missing fields")
            return

        msg = {'type': 'connect', 'phase': request['phase'] + 1, 'ciphers': ['NONE'], 'done': ""}

        if 'NONE' not in request['ciphers']:
            logging.info("Connect continue to phase " + str(msg['phase']))

            # phase 1: send public asymmetric cipher to client
            if int(request['phase']) == 1:
                logging.info("Processing phase 2 connect")
                # send public part of our asymmetric cipher
                sender.handshake_aKey = csc_generate_aPrivKey()
                msg['data'] = csc_get_pem_from_aPriKey(sender.handshake_aKey)

                intersection = list(set(request['ciphers']) & set(SUPPORTED_CIPHERS))

                if len(intersection) is 0:
                    logging.error("No compatible encryption protocols")

                msg['ciphers'] = [random.choice(intersection)]
                sender.send(msg)
                return

            # phase 3: generate symmetric cipher from user secret and iv
            if int(request['phase']) == 3:
                logging.info("Processing phase 3 connect")
                password, iv = csc_asymDec_unpickle(sender.handshake_aKey, request['data'])
                sender.key = password
                sender.cipher = csc_generate_symKey(password, iv)
                data_signature = request['data_signature']
                public_key = request['public_key']
                public_key_signature = request['public_key_signature']
                sender.x509 = request['x509']
                sender.x509_chain = request['x509_chain']

                # validate signature
                csc_aPublic_validate_signature(request['data'], data_signature, public_key)
                csc_validate_x509_signature(public_key, public_key_signature, sender.x509)
                logging.debug("Validated client signature")

                # validate chain
                csc_validate_chain(sender.x509_chain, sender.x509)
                logging.debug("Validated client chain up to CA root and against crl.")

                msg['done'] = "ok"
                sender.send(msg)

        self.verifyClient(str(request['id']), sender)

        self.id2client[request['id']] = sender
        sender.id = request['id']
        sender.name = request['name']
        sender.state = Connection.STATE_CONNECTED
        sender.security_level = Connection.SECURITY_STATE_AUTHENTICATED
        logging.info("Client %s Connected and authenticated" % request['id'])

    # TODO print with logger.debug
    def verifyClient(self, client_id, sender):

        if client_id in self.id2client:
            print "Client already exists!"
            print self.id2client[client_id]
            self.delClient(sender.socket)
        else:
            print "Client doens't exist!"

    def processList(self, sender, request):
        """
        Process a list message from a client
        """
        if sender.state != Connection.STATE_CONNECTED:
            logging.warning("LIST from disconnected client: %s" % sender)
            return

        enc, hmac = csc_pickle_symEnc(sender.cipher,
                                      sender.key,
                                      {'type': 'list',
                                       'data': self.clientList(),
                                       })

        sender.send({'type': 'secure',
                     'payload': enc,
                     'hmac': hmac
                     })

    def processWhois(self, sender, request):
        if sender.state != Connection.STATE_CONNECTED:
            logging.warning("LIST from disconnected client: %s" % sender)
            return

        print request['user']
        print self.clientList()
        print self.id2client
        print self.connections

        if request['user'] in self.id2client:
            request = self.id2client[request['user']]

            enc, hmac = csc_pickle_symEnc(sender.cipher,
                                          sender.key,
                                          {'type': 'whois-response',
                                           'data': request.x509,
                                           })

            sender.send({'type': 'secure',
                         'payload': enc,
                         'hmac': hmac
                         })

    def processSecure(self, sender, request):
        """
        Process a secure message from a client
        """
        if sender.state != Connection.STATE_CONNECTED:
            logging.warning("SECURE from disconnected client: %s" % sender)
            return

        if 'payload' not in request:
            logging.warning("Secure message with missing fields")
            return

        # This is a secure message.
        request['payload'] = csc_symDec_unpickle(sender.cipher,
                                                 sender.key,
                                                 request['hmac'],
                                                 request['payload'])

        logging.info("Decrypted message from %s: %r", sender, repr(request))

        if 'type' not in request['payload'].keys():
            logging.warning("Secure message without inner frame type")
            return

        if request['payload']['type'] == 'list':
            self.processList(sender, request['payload'])
            return

        if request['payload']['type'] == 'whois-get':
            self.processWhois(sender, request['payload'])
            return

        if not all(k in request['payload'].keys() for k in ("src", "dst")):
            return

        if not request['payload']['dst'] in self.id2client.keys():
            logging.warning("Message to unknown client: %s" % request['payload']['dst'])
            return

        dst = self.id2client[request['payload']['dst']]

        enc, hmac = csc_pickle_symEnc(dst.cipher, dst.key, request['payload'])

        dst_message = {'type': 'secure',
                       'payload': enc,
                       'hmac': hmac,
                       'src-id': id(sender)
                       }

        dst.send(dst_message)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        PORT = int(sys.argv[1])

    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                        formatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    serv = None
    while True:
        try:
            logging.info("Starting Secure IM Server v1.0")
            serv = Server(HOST, PORT)
            serv.loop()
        except KeyboardInterrupt:
            serv.stop()
            try:
                logging.info("Press CTRL-C again within 2 sec to quit")
                time.sleep(2)
            except KeyboardInterrupt:
                logging.info("CTRL-C pressed twice: Quitting!")
                break
        except:
            logging.exception("Server ERROR")
            if serv is not None:
                serv.stop()
            time.sleep(10)
