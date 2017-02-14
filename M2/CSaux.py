import base64
import json
import logging
import pickle
from socket import AF_INET, SOCK_STREAM, socket


def dic_pickle_dumps_and_b64(data):
    """
    Pickles and base64 all data in a dictionary
    Used before sending an json over a socket
    :param data: to encode
    :return: encoded data
    """
    for i in data:
        data[i] = base64.b64encode(pickle.dumps(data[i]))
    return data


def dic_b64_and_pickle_loads(data):
    """
    Base64 decodes and unpickles all data in a dictionary
    :param data: dictionary to pickle loads
    :return: native data
    """
    for i in data:
        data[i] = pickle.loads(base64.b64decode(data[i]))
    return data


class Message:
    """
    Message encapsulation that contains message status
    """
    __status = {
        0: "SENT",
        1: "DELIVERED",
        2: "READ"
    }

    def __init__(self, message):
        self.__dict__['text'] = message
        self.__dict__['status'] = self.__status[0]
        self.status = self.__dict__['status']
        self.text = self.__dict__['text']
        self.id = id(self)

    def __str__(self):
        return str(self.__dict__['text'])

    def delivered(self):
        self.__dict__['status'] = self.__status[1]

    def read(self):
        self.__dict__['status'] = self.__status[2]

    def __getitem__(self, key):
        return self.__dict__[key]

    def __setitem__(self, key, value):
        self.__dict__[key] = value


class Connection(object):
    """
    Abstracts a connection for ChatSecure and for Server
    """
    count = 0

    SECURITY_STATE_PLAINTEXT = 0
    SECURITY_STATE_AUTHENTICATED = 1

    STATE_NONE = 0
    STATE_CONNECTED = 1
    STATE_DISCONNECTED = 2

    TERMINATOR = "\n\n"
    BUFSIZE = 512 * 1024
    MAX_BUFSIZE = 1024 * 1024

    def __init__(self, sockt=socket(AF_INET, SOCK_STREAM), addr=None, name="Unknown", id=0):
        self.socket = sockt
        self.bufin = ""
        self.bufout = ""
        self.addr = addr
        self.sa_data = None
        self.state = Connection.STATE_NONE
        self.name = name
        self.id = id
        self.message_history = {}

        # Private RSA asymmetric key to use when exchanging keys
        self.user_aKey = None
        """:type user_aKey: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey """

        # secure level to determine what is the connection status with another user
        self.security_level = Connection.SECURITY_STATE_PLAINTEXT

        # Symmetric cypher object that encrypts/decrypts data for the session
        self.cipher = None

        # Key used to generate cypher object and to validate HMAC data
        self.key = None
        """:type key: bytearray """

        # Asymmetric key used to establish session key (self.cipher) and secret (self.key) with the client
        self.handshake_aKey = None
        """:type handshake_aKey: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey"""

        # connection certificate pem
        self.x509 = ""

        # connection certificate pem chain up to CA Root
        self.x509_chain = []

    def __str__(self):
        """ Converts object into string.
        """
        return "Client(id=%r addr:%s name:%s level:%d state:%d)" % (
            self.id, str(self.addr), self.name, self.security_level, self.state)

    def asDict(self):
        return {'id': self.id, 'level': self.security_level}

    def setState(self, state):
        if state not in [Connection.STATE_CONNECTED, Connection.STATE_NONE, Connection.STATE_DISCONNECTED]:
            return

        self.state = state

    def parseReqs(self, data):
        """Parse a chunk of data from this client.
        Return any complete requests in a list.
        Leave incomplete requests in the buffer.
        This is called whenever data is available from client socket."""

        if len(self.bufin) + len(data) > Connection.MAX_BUFSIZE:
            logging.error("Client (%s) buffer exceeds MAX BUFSIZE. %d > %d",
                          (self, len(self.bufin) + len(data), Connection.MAX_BUFSIZE))
            self.bufin = ""

        self.bufin += data
        reqs = self.bufin.split(Connection.TERMINATOR)
        self.bufin = reqs[-1]
        return reqs[:-1]

    def send(self, obj):
        """Send an object to this client.
        """
        try:
            obj = dic_pickle_dumps_and_b64(obj)
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

        logging.info("Connection Closed")


class Communications(object):
    """
    Abstracts socket functions both for ChatSecure and Server
    """

    def flushout(self, s):
        """Write a chunk of data to client.
        This is called whenever client socket is ready to transmit data."""
        if s not in self.connections:
            # this could happen before, because a flushin might have deleted the client
            logging.error("BUG: Flushing out socket that is not on client list! Socket=%s", str(s))
            return

        client = self.connections[s]
        try:
            sent = client.socket.send(client.bufout[:Connection.BUFSIZE])
            logging.info("Sent %d bytes to %s. Message:\n%r", sent, client, client.bufout[:sent])
            client.bufout = client.bufout[sent:]  # leave remaining to be sent later
        except:
            logging.exception("flushout: send(%s)", client)
            # logging.error("Cannot write to client %s. Closing", client)
            self.delClient(client.socket)

    def flushin(self, s):
        """Read a chunk of data from this client.
        Enqueue any complete requests.
        Leave incomplete requests in buffer.
        This is called whenever data is available from client socket.
        """
        client = self.connections[s]

        try:
            data = s.recv(Connection.BUFSIZE)
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
                self.delClient(s, exists=True)

    def handleRequest(self, s, request):
        """Handle a request from a client socket.
        """
        client = self.connections[s]

        try:
            logging.info("HANDLING message from %s: %r", client, repr(request))

            try:
                req = json.loads(request)
                req = dic_b64_and_pickle_loads(req)
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

        except Exception:
            logging.exception("Could not handle request")