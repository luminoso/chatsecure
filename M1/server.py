# encoding: utf-8
#
# jpbarraca@ua.pt
# jmr@ua.pt 2016

# vim settings:
# :set expandtab ts=4

from socket import *
from select import *
import json
import sys
import time
import logging
import os
import random
from CScrypto import *

# Server address
HOST = ""  # All available interfaces
PORT = 8080  # The server port

BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 64 * 1024

STATE_NONE = 0
STATE_CONNECTED = 1
STATE_DISCONNECTED = 2
RANDOM_ENTROPY_GENERATOR_SIZE = 32
SUPPORTED_CIPHERS = ["RSA_NONE_AES128_CBC_HMAC", "RSA_NONE_AES256_CBC_HMAC"]

class Client:
    count = 0

    def __init__(self, socket, addr):
        self.socket = socket
        self.bufin = ""
        self.bufout = ""
        self.addr = addr
        self.id = None
        self.sa_data = None
        self.level = 0
        self.state = STATE_NONE
        self.name = "Unknown"

        # Cipher object for the client. Used to encrypt/decrypt session data
        self.cipher = None
        """:type cipher: cryptography.hazmat.primitives.ciphers.Cipher"""

        # Secret used to generate cipher and to validate HMAC messages
        self.key = None
        """:type key: bytearray"""

        # Asymmetric key used to establish session key (self.cipher) and secret (self.key) with the client
        self.handshake_aKey = None
        """:type handshake_aKey: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey"""

    def __str__(self):
        """ Converts object into string.
        """
        return "Client(id=%r addr:%s name:%s level:%d state:%d)" % (
            self.id, str(self.addr), self.name, self.level, self.state)

    def asDict(self):
        return {'id': self.id, 'level': self.level}

    def setState(self, state):
        if state not in [STATE_CONNECTED, STATE_NONE, STATE_DISCONNECTED]:
            return

        self.state = state

    def parseReqs(self, data):
        """Parse a chunk of data from this client.
        Return any complete requests in a list.
        Leave incomplete requests in the buffer.
        This is called whenever data is available from client socket."""

        if len(self.bufin) + len(data) > MAX_BUFSIZE:
            logging.error("Client (%s) buffer exceeds MAX BUFSIZE. %d > %d",
                          (self, len(self.bufin) + len(data), MAX_BUFSIZE))
            self.bufin = ""

        self.bufin += data
        reqs = self.bufin.split(TERMINATOR)
        print reqs
        self.bufin = reqs[-1]
        return reqs[:-1]

    def send(self, obj):
        """Send an object to this client.
        """
        try:
            self.bufout += json.dumps(obj) + "\n\n"
        except:
            # It should never happen! And not be reported to the client!
            logging.exception("Client.send(%s)", self)

    def close(self):
        """Shuts down and closes this client's socket.
        Will log error if called on a client with closed socket.
        Never fails.
        """
        logging.info("Client.close(%s)", self)
        try:
            self.socket.close()
        except:
            logging.exception("Client.close(%s)", self)

        logging.info("Client Closed")


class ChatError(Exception):
    """This exception should signal a protocol error in a client request.
    It is not a server error!
    It just means the server must report it to the sender.
    It should be dealt with inside handleRequest.
    (It should allow leaner error handling code.)
    """
    pass


def ERROR(msg):
    """Raise a Chat protocol error."""
    raise ChatError(msg)


class Server:
    def __init__(self, host, port):
        self.ss = socket(AF_INET, SOCK_STREAM)  # the server socket (IP \ TCP)
        self.ss.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.ss.bind((host, port))
        self.ss.listen(10)
        logging.info("Secure IM server listening on %s", self.ss.getsockname())
        # clients to manage (indexed by socket and by name):
        self.clients = {}  # clients (cipher is socket)
        self.id2client = {}  # clients (cipher is id)

    def stop(self):
        """ Stops the server closing all sockets
        """
        logging.info("Stopping Server")
        try:
            self.ss.close()
        except:
            logging.exception("Server.stop")

        for csock in self.clients:
            try:
                self.clients[csock].close()  # Client.close!
            except:
                # this should not happen since close is protected...
                logging.exception("clients[csock].close")

        # If we delClient instead, the following would be unnecessary...
        self.clients.clear()
        self.id2client.clear()

    def addClient(self, csock, addr):
        """Add a client connecting in csock."""
        if csock in self.clients:
            logging.error("Client NOT Added: %s already exists", self.clients[csock])
            return

        client = Client(csock, addr)
        self.clients[client.socket] = client
        logging.info("Client added: %s", client)

    def delClient(self, csock):
        """Delete a client connected in csock."""
        if csock not in self.clients:
            logging.error("Client NOT deleted: %s not found", self.clients[csock])
            return

        client = self.clients[csock]
        assert client.socket == csock, "client.socket (%s) should match cipher (%s)" % (client.socket, csock)

        client.socket.send("Client name already exists, exiting...")

        if client.id in self.id2client.keys():
            del self.id2client[client.id]

        del self.clients[client.socket]
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

    def flushin(self, s):
        """Read a chunk of data from this client.
        Enqueue any complete requests.
        Leave incomplete requests in buffer.
        This is called whenever data is available from client socket.
        """
        client = self.clients[s]
        data = None
        try:
            data = s.recv(BUFSIZE)
            logging.info("Received data from %s. Message:\n%r", client, data)
        except:
            logging.exception("flushin: recv(%s)", client)
            logging.error("Received invalid data from %s. Closing", client)
            self.delClient(s)
        else:
            if len(data) > 0:
                reqs = client.parseReqs(data)
                for req in reqs:
                    self.handleRequest(s, req)
            else:
                self.delClient(s)

    def flushout(self, s):
        """Write a chunk of data to client.
        This is called whenever client socket is ready to transmit data."""
        if s not in self.clients:
            # this could happen before, because a flushin might have deleted the client
            logging.error("BUG: Flushing out socket that is not on client list! Socket=%s", str(s))
            return

        client = self.clients[s]
        try:
            sent = client.socket.send(client.bufout[:BUFSIZE])
            logging.info("Sent %d bytes to %s. Message:\n%r", sent, client, client.bufout[:sent])
            client.bufout = client.bufout[sent:]  # leave remaining to be sent later
        except:
            logging.exception("flushout: send(%s)", client)
            # logging.error("Cannot write to client %s. Closing", client)
            self.delClient(client.socket)

    def loop(self):
        while True:
            # sockets to select for reading: (the server socket + every open client connection)
            rlist = [self.ss] + self.clients.keys()
            # sockets to select for writing: (those that have something in bufout)
            wlist = [sock for sock in self.clients if len(self.clients[sock].bufout) > 0]
            logging.debug("select waiting for %dR %dW %dX", len(rlist), len(wlist), len(rlist))
            (rl, wl, xl) = select(rlist, wlist, rlist)
            logging.debug("select: %s %s %s", rl, wl, xl)

            # Deal with incoming data:
            for s in rl:
                if s is self.ss:
                    self.accept()
                elif s in self.clients:
                    self.flushin(s)
                else:
                    logging.error("Incoming, but %s not in clients anymore", s)

            # Deal with outgoing data:
            for s in wl:
                if s in self.clients:
                    self.flushout(s)
                else:
                    logging.error("Outgoing, but %s not in clients anymore", s)

            for s in xl:
                logging.error("EXCEPTION in %s. Closing", s)
                self.delClient(s)

    def handleRequest(self, s, request):
        """Handle a request from a client socket.
        """
        client = self.clients[s]
        try:
            logging.info("HANDLING message from %s: %r", client, repr(request))

            try:
                req = json.loads(request)
            except:
                return

            if not isinstance(req, dict):
                return

            if 'type' not in req:
                return

            if req['type'] == 'ack':
                return  # Ignore for now

            client.send({'type': 'ack'})

            if req['type'] == 'connect':
                self.processConnect(client, req)
            elif req['type'] == 'secure':
                self.processSecure(client, req)

        except Exception, e:
            logging.exception("Could not handle request")

    def clientList(self):
        """
        Return the client list
        """
        cl = []
        for k in self.clients:
            cl.append(self.clients[k].asDict())

        return cl

    def processConnect(self, sender, request):
        """
        Process a connect message from a client
        """
        if sender.state == STATE_CONNECTED:
            logging.warning("Client is already connected: %s" % sender)
            return

        if not all(k in request.keys() for k in ("name", "ciphers", "phase", "id")):
            logging.warning("Connect message with missing fields")
            return

        msg = {'type': 'connect', 'phase': request['phase'] + 1, 'ciphers': ['NONE']}

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
                password, iv = csc_b64dec_asymDec_pickle(sender.handshake_aKey, request['data'])
                sender.key = password
                sender.cipher = csc_generate_symKey(password, iv)

        self.verifyClient(str(request['id']), sender)

        self.id2client[request['id']] = sender
        sender.id = request['id']
        sender.name = request['name']
        sender.state = STATE_CONNECTED
        logging.info("Client %s Connected" % request['id'])

    def verifyClient(self, client_id, sender):
        print len(self.clients)
        print str(self.id2client)

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
        if sender.state != STATE_CONNECTED:
            logging.warning("LIST from disconnected client: %s" % sender)
            return

        enc, hmac = csc_pickle_symEnc_b64enc(sender.cipher,
                                             sender.key,
                                             {'type': 'list',
                                              'data': self.clientList(),
                                              "random-data": pickle.dumps(os.urandom(RANDOM_ENTROPY_GENERATOR_SIZE))
                                              })

        sender.send({'type': 'secure',
                     'payload': enc,
                     'hmac': hmac
                     })

    def processSecure(self, sender, request):
        """
        Process a secure message from a client
        """
        if sender.state != STATE_CONNECTED:
            logging.warning("SECURE from disconnected client: %s" % sender)
            return

        if 'payload' not in request:
            logging.warning("Secure message with missing fields")
            return

        # This is a secure message.
        request['payload'] = csc_b64dec_symDec_pickle(sender.cipher,
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

        if not all(k in request['payload'].keys() for k in ("src", "dst")):
            return

        k = self.id2client.keys()
        if not request['payload']['dst'] in self.id2client.keys():
            logging.warning("Message to unknown client: %s" % request['payload']['dst'])
            return

        dst = self.id2client[request['payload']['dst']]

        request['payload']['random-data'] = pickle.dumps(os.urandom(RANDOM_ENTROPY_GENERATOR_SIZE))

        enc, hmac = csc_pickle_symEnc_b64enc(dst.cipher, dst.key, request['payload'])

        dst_message = {'type': 'secure',
                       'payload': enc,
                       'hmac': hmac
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
