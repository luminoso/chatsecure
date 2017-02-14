# encoding: utf-8

import hashlib
import json
import logging
import random
import sys
import os
import re  # regex
from select import *
from socket import *
from time import strftime  # print time

from CScrypto import *

BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 64 * 1024
JSON = "JSON"
BASE64 = "BASE64"
INPUT_TIMEOUT = 1
RANDOM_ENTROPY_GENERATOR_SIZE = 32

SECURITY_STATE_PLAINTEXT = 0
SECURITY_STATE_ENCRYPTED = 1


class Client:
    def __init__(self, name):
        self.name = name

        # Private RSA asymmetric key to use when exchanging keys
        self.user_aKey = None
        """:type user_aKey: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey """

        # secure level to determine what is the connection status with another user
        self.security_level = SECURITY_STATE_PLAINTEXT

        # Symmetric cypher object that encrypts/decrypts data for the session
        self.cipher = None
        """:type cipher: cryptography.hazmat.primitives.ciphers.Cipher"""

        # Key used to generate cypher object and to validate HMAC data
        self.key = None
        """:type key: bytearray """


class ChatSecure(object):
    name = ""
    id = int(random.randint(0, 5))
    conn = socket(AF_INET, SOCK_STREAM)
    server = "127.0.0.1"
    port = 8080
    bufin = ""
    bufout = ""
    ok = True

    # Temporary public asymmetric cipher of the server
    server_aKey = None
    """:type server_key: cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey"""

    # Symmetric cipher shared with the server to encrypt session data
    server_cipher = None

    # Server secret used to generate server_cipher and to validate HMAC messages
    server_key = None
    """:type server_key: bytearray """

    connected_clients = {}
    tmp_buffer = ""

    def __init__(self):
        self.printing_list = True
        try:
            import sys
            if (sys.argv[1] == "debug"):
                logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                                    formatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        except:
            pass

    def start(self):
        # ask for credentials and init connection
        self.initConnection()

    def initConnection(self):
        """
        Asks for username
        Init the comunication and registration with the server
        """

        while True:
            print "Name: ",
            name_tmp = raw_input()

            if name_tmp == "":
                print "Name must contain at least one letter!"
            else:
                self.name = name_tmp
                break

        # TODO: mostrar lista de cifras

        try:
            self.conn.connect((self.server, self.port))
        except:
            logging.exception("Couldn't establish connection. Exiting")
            exit(1)

        # register ourselfs in the server:
        connnect_message = {"type": "connect",
                            "phase": 1,
                            "name": self.name,
                            "id": self.name,
                            "ciphers": ["RSA_NONE_AES128_CBC_HMAC", "RSA_NONE_AES256_CBC_HMAC"],
                            "data": ""}
        # send registration
        self.send(connnect_message)

        # enter main loop
        self.loop()

    def processConnect(self, req):
        """
        Process the end of crypto negotiations with the server
        Phase 2: receive server public cipher, send our symmetric cipher secret and iv
        :param req: json
        :return: nothing
        """
        logging.debug("Connect phase >1")

        if not isinstance(req, dict):
            logging.error("Malformed connect phase > 1 data")
            return

        if req['type'] != 'connect' or req['phase'] <= 1:
            logging.error("Unexpected message type {} in connect phase", req['type'])

        if req['phase'] == 2:
            # get server asymmetric public cipher
            try:
                self.server_aKey = csc_get_aPubKey_from_pem(str(req['data']))
            except:
                logging.exception("Unable to generate server public cipher:%d" + req['data'])
                exit(1)

            # present cipher to user and let them decide if ok
            h = hashlib.sha256()
            h.update(req['data'])

            print "Server cipher sha256 fingerprint is: " + h.hexdigest()
            print "Confirm (y/n)? ",
            confirmation = sys.stdin.readline().splitlines()

            # confirmation = "y"
            if confirmation[0] == "n":
                print "Not secure. exiting"
                exit(0)

            # Generate and symmetric cipher and send KEY and IV
            if req['ciphers'][0] == "RSA_NONE_AES128_CBC_HMAC":
                self.server_key = os.urandom(16)
                logging.debug("Using 128bit key")
            else:
                self.server_key = os.urandom(32)
                logging.debug("Using 256bit key")

            iv = os.urandom(16)
            self.server_cipher = csc_generate_symKey(self.server_key, iv)

            connect_message = {"type": "connect",
                               "phase": req['phase'] + 1,
                               "name": self.name,
                               "id": self.name,
                               "ciphers": ["RSA_NONE_AES128_CBC_HMAC", "RSA_NONE_AES256_CBC_HMAC"],
                               "data": csc_pickle_asymEnc_b64enc(self.server_aKey, [self.server_key, iv])
                               }

            self.send(connect_message)

            self.printPrompt(True)

            return

        if req['phase'] > 2:
            # TODO: receive ack?
            logging.debug("Unimplemented processConnect phase:%d", req['phase'])
            return

    def payload_list_users(self):
        """
        Requests list of users from server
        Reply from server is processed at processSecure()
        """
        list_message = {"type": "list",
                        "data": [],
                        "random-data": pickle.dumps(os.urandom(RANDOM_ENTROPY_GENERATOR_SIZE))}  # generate entropy
        self.sendSecure(list_message)

    def sendACK(self):
        """
        Sends a ACK to server
        """
        message = {"type": "ack"}

        self.send(message)

    def payload_client_com(self, dest, message):
        """
        Sends a message to user
        :param dest: user id to send the message
        :param message: to send
        """

        # 1. do we recognize user?
        if dest not in self.connected_clients:
            print "User not recognized. Type 'list' to list users"
            return

        # 2. identify client
        destination_user = self.connected_clients[dest]
        """:type : Client"""

        # 3. Do we have a secure connection to user? If not, initialize connection
        if destination_user.security_level is not SECURITY_STATE_ENCRYPTED:
            logging.info("Connecting to user " + destination_user.name)
            self.tmp_buffer = message
            self.connect_to_client(destination_user)
            return

        # 3. If everything ok, send the message

        enc, hmac = csc_pickle_symEnc_b64enc(destination_user.cipher, destination_user.key, message)

        message = {"type": "client-com",
                   "src": self.name,
                   "dst": dest,
                   "data": enc,
                   "hmac": hmac,
                   "random-data": pickle.dumps(os.urandom(RANDOM_ENTROPY_GENERATOR_SIZE))}  # generate entropy

        self.sendSecure(message)

    def connect_to_client(self, client, req=None):
        """
        Performs connection handshake with client using diff hellman
        :param client: to connect to
        :type client: Client
        :param req: request data
        """

        # Phase 1: Send a message to client with our public cipher
        if req is None:
            logging.info("Client connect handshake phase 1")

            client.user_aKey = csc_generate_aPrivKey()

            logging.debug("Sending to " + client.name + " public bits")

            client_connect_message = {"type": "client-connect",
                                      "src": self.name,
                                      "dst": client.name,
                                      "phase": 1,
                                      "ciphers": ["AES"],
                                      "data": csc_get_pem_from_aPriKey(client.user_aKey)}

            self.sendSecure(client_connect_message)
            return

        # Phase 2: We receive an connection with an RSA Public cipher
        if req['phase'] == 1:
            logging.info("Client connect phase 2 with user")

            tmp_public_aKey = csc_get_aPubKey_from_pem(req['data'])

            print "User " + str(req['src']) + " wants to communicate"
            # print "User cipher fingerprint: " + self.lineToFingerprint(req['data'])
            # print "Confirm? (y/n)"
            # TODO accept or not

            # is the user already recognized ?
            if req['src'] not in self.connected_clients:
                self.connected_clients[req['src']] = Client(req['src'])

            client = self.connected_clients[req['src']]
            client.security_level = SECURITY_STATE_ENCRYPTED
            client.key = os.urandom(32)
            iv = os.urandom(16)
            client.cipher = csc_generate_symKey(client.key, iv)

            # note that asymEnc doesn't need appended random data(?)
            client_connect_message = {"type": "client-connect",
                                      "src": self.name,
                                      "dst": client.name,
                                      "phase": 2,
                                      "ciphers": ["DH"],
                                      "data": csc_pickle_asymEnc_b64enc(tmp_public_aKey, [client.key, iv]),
                                      }

            self.sendSecure(client_connect_message)
            return

        # Phase 3: Get password and iv for symmetric cipher
        if req['phase'] == 2:
            client = self.connected_clients[req['src']]
            logging.info("Client connect phase 3 with user:" + client.name)

            password, iv = csc_b64dec_asymDec_pickle(client.user_aKey, req['data'])
            client.key = password
            client.cipher = csc_generate_symKey(password, iv)
            client.security_level = SECURITY_STATE_ENCRYPTED
            logging.info("Client " + client.name + "is now securely connected")

            if len(self.tmp_buffer) > 0:
                self.payload_client_com(req['src'], self.tmp_buffer)

            return

    def sendSecure(self, message):
        """
        Encapsulates an message in the secure id message format
        :param message: to send in the secure protocol
        """

        # TODO sa-data for base64
        secure_message = {"type": "secure",
                          "sa-data": JSON,
                          "payload": "",
                          }

        enc, hmac = csc_pickle_symEnc_b64enc(self.server_cipher, self.server_key, message)
        secure_message['payload'] = enc
        secure_message['hmac'] = hmac

        self.send(secure_message)

    def processSecure(self, request):
        """
        Process a secure message from a client
        """

        if 'payload' not in request:
            logging.warning("Secure message with missing fields")
            return

        # This is a secure message.
        request['payload'] = csc_b64dec_symDec_pickle(self.server_cipher,
                                                      self.server_key,
                                                      request['hmac'],
                                                      request['payload'])

        if 'type' not in request['payload'].keys():
            logging.warning("Secure message without inner frame type")
            return

        if request['payload']['type'] == 'list':
            print ""
            i = 1
            print "User list:"
            for users in request['payload']['data']:
                if users['id'] not in self.connected_clients and users['id'] not in self.name:
                    logging.debug("Recognizing a new user: " + users['id'])
                    self.connected_clients[users['id']] = Client(users['id'])
                print '{}. ID: {} Level: {}'.format(i, users['id'], users['level'])
                i += 1
            print ""
            self.printPrompt()

        # TODO: client-connect
        if request['payload']['type'] == 'client-connect':
            self.connect_to_client(None, request['payload'])
            return

        # TODO: client-disconnect
        if request['payload']['type'] == 'client-disconnect':
            logging.debug("Unimplemented payload:%d", request['payload']['type'])
            return

        # TODO: client communication
        if request['payload']['type'] == 'client-com':
            logging.debug("Unimplemented payload:%d" + request['payload']['type'])

            # decrypt message
            client = self.connected_clients[request['payload']['src']]
            request['payload']['data'] = csc_b64dec_symDec_pickle(client.cipher,
                                                                  client.key,
                                                                  request['payload']['hmac'],
                                                                  request['payload']['data'])

            self.printPrompt(True, '[{}] [{}]: {}'.format(strftime("%H:%M:%S"), request['payload']['src'],
                                                          request['payload']['data']))
            return

        # TODO: ack
        if request['payload']['type'] == 'ack':
            logging.debug("Unimplemented payload:%d", request['payload']['type'])
            return

    def handleRequest(self, s, request):
        """Handle a request from a client socket.
        """

        try:
            logging.info("HANDLING message: %r", repr(request))

            try:
                req = json.loads(request)
            except:
                return

            if not isinstance(req, dict):
                return

            if 'type' not in req:
                return

            if req['type'] == 'ack':
                logging.info("Received ACK")
                return  # Ignore for now

            self.send({'type': 'ack'})

            # TODO implement more features
            if req['type'] == 'connect':
                self.processConnect(req)
                return
            elif req['type'] == 'secure':
                self.processSecure(req)
                return

            if req['type'] == 'list':
                print req
                return

        except Exception, e:
            logging.exception("Could not handle request")

    #
    #
    # FROM HERE, NO NEED TO EDIT FUNCTIONS
    #
    #
    @staticmethod
    def lineToFingerprint(line):
        key = base64.b64decode(line.strip().split()[1].encode('ascii'))
        fp_plain = hashlib.md5(key).hexdigest()
        return ':'.join(a + b for a, b in zip(fp_plain[::2], fp_plain[1::2]))

    def printPrompt(self, clear=False, print_before=""):
        """
        Prints prompt with time, user name and user id
        :return:
        """
        if clear:
            for _ in range(128):
                sys.stdout.write("\r")
            sys.stdout.flush()

        if len(print_before) > 0:
            print print_before

        print '[{}] [{}-{}] '.format(strftime("%H:%M:%S"), self.name, self.id),
        sys.stdout.flush()

    def loop(self):
        while True:
            # sockets to select for reading: (the server socket + user input if any)
            rlist = [self.conn] + [sys.stdin]

            # (check if we have something in queued in bufout to send)
            wlist = [self.conn] if len(self.bufout) > 0 else []

            # wait for something to happen
            (rl, wl, xl) = select(rlist, wlist, rlist)

            f = (lambda a: "1" if a else "0")  # print select status with 1s and 0s)
            logging.debug("select: %s %s %s", f(rl), f(wl), f(xl))

            # Deal with incoming data:
            for s in rl:
                # is it a socket in that just happened?
                if isinstance(s, socket):
                    self.flushin(s)
                else:
                    # if not then it must be user input
                    s = sys.stdin.readline().splitlines()  # split lines avoids \n at the end

                    # check if there's really anything or just a return
                    if len(s) > 0 and len(s[0]) > 0:
                        self.processInput(s[0])
                    else:
                        # just a return? ok, remove return char and print a new prompt line
                        self.printPrompt(True)

            # Deal with outgoing data:
            if wlist:
                self.flushout(self.conn)

            # deal with errors
            for s in xl:
                logging.error("EXCEPTION in %s. Closing", s)
                self.conn.close()

    def printHelp(self):
        """
        Prints help to terminal (usually when user inputs a wrong command
        """
        print ""
        print "Available commands are:"
        print "list"
        print "help"
        print ""
        print "Syntax for sending message to 'john':"
        print "john: hello there"
        print ""
        self.printPrompt()

    def processInput(self, input):
        """
        Process user input at the terminal commands or message to someone
        :param input: to process
        """

        # recognized commands
        if input == 'list':
            self.payload_list_users()
            return

        if input == 'help':
            self.printHelp()
            return

        if input == 'exit' or input == 'quit':
            print "Exiting.."
            self.close()
            exit(0)

        # recognize send a message to someone in the format user: message
        match = re.search(r"(?P<dest>[^:]*):(?P<message>.*)", input)
        if match:
            dest = match.group("dest")
            message = match.group("message")
            if dest and message:
                self.payload_client_com(dest, message)
                self.printPrompt(True)
                return

        # if no command or unrecognized command just print help
        self.printHelp()

    def flushin(self, s):
        """Read a chunk of data from this client.
        Enqueue any complete requests.
        Leave incomplete requests in buffer.
        This is called whenever data is available from client socket.
        """

        data = None
        try:
            data = s.recv(BUFSIZE)
            logging.info("Received data. Message: %r", data)
        except:
            logging.exception("flushin: recv data: ", data)
            logging.error("Received invalid data from server. Closing")
            self.conn.close()
        else:
            if len(data) > 0:
                reqs = self.parseReqs(data)
                for req in reqs:
                    self.handleRequest(s, req)
            else:
                logging.debug("Received empty data from server? len:%d, data:%s", len(data), data)
                exit(1)

    def flushout(self, s):
        """Write a chunk of data to client.
        This is called whenever client socket is ready to transmit data."""
        if s is None:
            # this could happen before, because a flushin might have deleted the client
            logging.error("BUG: Flushing out socket that is closed. Socket=%s", str(s))
            return

        try:
            sent = self.conn.send(self.bufout[:BUFSIZE])
            logging.info("Sent %d bytes to server. Message: %r", sent, self.bufout[:sent])
            self.bufout = self.bufout[sent:]  # leave remaining to be sent later
        except:
            logging.exception("flushout failed: send(%s)")
            self.conn.close()

    def get_buffin(self):
        return self.bufin

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
        self.conn.close()


if __name__ == "__main__":
    cs = ChatSecure()
    try:
        cs.start()
    except KeyboardInterrupt:
        print ""
        print "Exiting..."
        cs.close()
