# -*- coding: utf-8 -*-

import base64
import hashlib
import logging
import re  # regex
import sys
from select import select
from socket import socket, AF_INET, SOCK_STREAM
from time import strftime  # print time

from CSaux import Message, Connection, Communications
from CScrypto import *
from PKCS11_Wrapper import PKCS11Wrapper


class ChatSecure(Connection, Communications):
    connections = {}  # just to server
    connected_clients = {}  # users we're talking to

    def __init__(self):

        super(ChatSecure, self).__init__(id=id(self))

        try:
            if sys.argv[1] == "debug":
                self.wrapper = PKCS11Wrapper(True)

            logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                                formatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        except IndexError:
            self.wrapper = PKCS11Wrapper()

        self.x509_chain = [self.wrapper.get_certificate_pem(i) for i in self.wrapper.get_available_certs_as_list()]
        self.x509 = self.wrapper.get_certificate_pem()
        self.aPriv = csc_generate_aPrivKey()
        self.aPubl_signature = self.wrapper.sign(csc_get_pem_from_aPriKey(self.aPriv))

    def start(self, server_ip, server_port):
        """
        Starts chat secure, by connecting to an server
        :param server_ip: ip of the server
        :param server_port: port of the server
        """

        self.server_ip = server_ip
        self.server_port = server_port

        while True:
            print "Name: ",
            name_tmp = raw_input()

            if name_tmp == "":
                print "Name must contain at least one letter!"
            else:
                self.name = name_tmp
                break

        try:
            self.socket.connect((server_ip, server_port))
            self.connections[self.socket] = self
        except:
            logging.exception("Couldn't establish connection. Exiting")
            exit(1)

        # register ourselves in the server:
        connect_message = {"type": "connect",
                           "phase": 1,
                           "name": self.name,
                           "id": self.name,
                           "ciphers": ["RSA_NONE_AES128_CBC_HMAC", "RSA_NONE_AES256_CBC_HMAC"],
                           "data": ""}
        # send registration
        self.send(connect_message)

        # enter main loop
        self.loop()

    def processConnect(self, sender, req):
        """
        Process the end of crypto negotiations with the server
        Phase 2: receive server public cipher, send our symmetric cipher secret and iv
        :param req: json
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

            symm_data = csc_pickle_asymEnc(self.server_aKey, [self.server_key, iv])

            connect_message = \
                {"type": "connect",
                 "phase": req['phase'] + 1,
                 "name": self.name,
                 "id": self.name,
                 "ciphers": ["RSA_NONE_AES128_CBC_HMAC", "RSA_NONE_AES256_CBC_HMAC"],
                 "data": symm_data,
                 "data_signature": csc_aPrivate_sign(self.aPriv, symm_data),
                 "public_key": csc_get_pem_from_aPriKey(self.aPriv),
                 "public_key_signature": self.aPubl_signature,
                 "x509_chain": self.x509_chain,
                 "x509": self.x509
                 }

            self.send(connect_message)

            #self.printPrompt()

            return

        if req['phase'] > 2:
            if req['done'] == "ok":
                self.printPrompt("Connection successfully established to server!\n")

            # TODO: receive ack?
            # logging.debug("Unimplemented processConnect phase:%d", req['phase'])
            return

    def payload_list_users(self):
        """
        Requests list of users from server
        Reply from server is processed at processSecure()
        """

        list_message = {
            "type": "list",
            "data": []
        }
        self.sendSecure(list_message)

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
        if destination_user.security_level is not Connection.SECURITY_STATE_AUTHENTICATED:
            logging.info("Connecting to user " + destination_user.name)
            self.tmp_buffer = message
            self.connect_to_client(destination_user)
            return

        # 3. If everything ok, send the message
        message = Message(message)

        enc, hmac = csc_pickle_symEnc(destination_user.cipher, destination_user.key, message)

        comm = {
            "type": "client-com",
            "src": self.name,
            "dst": dest,
            "data": enc,
            "hmac": hmac,
            "id": message.id,
        }

        destination_user.message_history[message.id] = message

        self.sendSecure(comm)

    def whois(self, user):
        if user not in self.connected_clients:
            print "User not recognized. Type 'list' to list users"
            return

        comm = {
            "type": "whois-get",
            "user": user
        }

        self.sendSecure(comm)

    def comm_ack(self, destination_user, message_id):
        # type: (Connection, int) -> ()
        """
        Sends a communication ACK for a message. (Delivery report)
        Also sends an random to derivate next key
        :param dest: user destination to send the delivery report
        :param message_id: id of the message which was read
        """

        enc, hmac = csc_pickle_symEnc(destination_user.cipher, destination_user.key, message_id)

        newkey, random = csc_derive_key(destination_user.key)
        destination_user.key = newkey
        destination_user.cipher = csc_generate_symKey(newkey, random)

        comm_ack = {
            "type": "comm-ack",
            "src": self.name,
            "dst": destination_user.name,
            "hmac": hmac,
            "data": enc,
            "next-key": random
        }

        self.sendSecure(comm_ack)

    def connect_to_client(self, client, req=None):
        """
        Performs connection handshake with client using diff hellman
        :param client: to connect to
        :type client: Connection
        :param req: request data
        """

        # Phase 1: Send a message to client with our public cipher
        if req is None:
            logging.info("Client connect handshake phase 1")

            client.user_aKey = csc_generate_aPrivKey()

            logging.debug("Sending to " + client.name + " public bits")

            symm_data = csc_get_pem_from_aPriKey(client.user_aKey)

            client_connect_message = \
                {"type": "client-connect",
                 "src": self.name,
                 "dst": client.name,
                 "phase": 1,
                 "ciphers": ["AES"],
                 "data": symm_data,
                 "data_signature": csc_aPrivate_sign(self.aPriv, symm_data),
                 "public_key": csc_get_pem_from_aPriKey(self.aPriv),
                 "public_key_signature": self.aPubl_signature,
                 "x509_chain": self.x509_chain,
                 "x509": self.x509
                 }

            self.sendSecure(client_connect_message)
            return

        # Phase 2: We receive a connection with an RSA Public cipher
        if req['phase'] == 1:
            logging.info("Client connect phase 2 with user")

            tmp_public_aKey = csc_get_aPubKey_from_pem(req['data'])

            logging.debug("Validating user " + req['src'] + " key signature")
            csc_validate_x509_signature(req['public_key'], req['public_key_signature'], req['x509'])

            logging.debug("Validating user " + req['src'] + " chain")

            self.printPrompt("User " + str(req['src']) + " wants to communicate: ")
            self.printPrompt(csc_pretty_cert_text(req['x509']))

            # print "Confirm? (y/n)"
            # TODO accept or not

            # is the user already recognized ?
            if req['src'] not in self.connected_clients:
                self.connected_clients[req['src']] = Connection(name=req['src'])

            client = self.connected_clients[req['src']]
            client.message_history = {}
            client.security_level = Connection.SECURITY_STATE_AUTHENTICATED
            client.key = os.urandom(32)
            iv = os.urandom(16)
            client.cipher = csc_generate_symKey(client.key, iv)

            symm_data = csc_pickle_asymEnc(tmp_public_aKey, [client.key, iv])

            client_connect_message = {
                "type": "client-connect",
                "src": self.name,
                "dst": client.name,
                "phase": 2,
                "ciphers": ["DH"],
                "data": symm_data,
                "data_signature": csc_aPrivate_sign(self.aPriv, symm_data),
                "public_key": csc_get_pem_from_aPriKey(self.aPriv),
                "public_key_signature": self.aPubl_signature,
                "x509_chain": self.x509_chain,
                "x509": self.x509
            }

            self.sendSecure(client_connect_message)
            return

        # Phase 3: Get password and iv for symmetric cipher
        if req['phase'] == 2:
            client = self.connected_clients[req['src']]
            logging.info("Client connect phase 3 with user:" + client.name)

            password, iv = csc_asymDec_unpickle(client.user_aKey, req['data'])
            client.key = password
            client.cipher = csc_generate_symKey(password, iv)
            client.security_level = Connection.SECURITY_STATE_AUTHENTICATED
            logging.info("Client " + client.name + "is now securely connected")

            # validate user by verifying signatures and chain
            logging.debug("Validating user " + req['src'] + " key signature")

            csc_aPublic_validate_signature(req['data'], req['data_signature'], req['public_key'])
            csc_validate_x509_signature(req['public_key'], req['public_key_signature'], req['x509'])

            logging.debug("Validating user " + req['src'] + " chain")
            csc_validate_chain(req['x509_chain'], req['x509'])

            self.printPrompt("Chain and signature validated!")
            self.printPrompt("User " + req['src'] + " identity is:")
            self.printPrompt(csc_pretty_cert_text(req['x509']))

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
                          # "sa-data": JSON,
                          "payload": "",
                          }

        enc, hmac = csc_pickle_symEnc(self.server_cipher, self.server_key, message)
        secure_message['payload'] = enc
        secure_message['hmac'] = hmac

        self.send(secure_message)

    def processSecure(self, sender, request):
        """
        Process a secure message from a client
        :param request: Secure payloaad to process
        """

        if 'payload' not in request:
            logging.warning("Secure message with missing fields")
            return

        # This is a secure message.
        request['payload'] = csc_symDec_unpickle(self.server_cipher,
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
                    self.connected_clients[users['id']] = Connection(name=users['id'])
                print '{}. ID: {} Level: {}'.format(i, users['id'], users['level'])
                i += 1

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
            # logging.debug("Unimplemented payload:%d" + request['payload']['type'])

            # decrypt message
            client = self.connected_clients[request['payload']['src']]
            request['payload']['data'] = csc_symDec_unpickle(client.cipher,
                                                             client.key,
                                                             request['payload']['hmac'],
                                                             request['payload']['data'])

            self.printPrompt('[{}] [{}]: {}\n'.format(strftime("%H:%M:%S"),
                                                      request['payload']['src'],
                                                      request['payload']['data']), True)

            self.comm_ack(client, request['payload']['data'].id)
            return

        if request['payload']['type'] == 'whois-response':
            self.printPrompt(csc_pretty_cert_text(request['payload']['data']))

        if request['payload']['type'] == 'comm-ack':
            # marks a message as read.
            # updates key

            client = self.connected_clients[request['payload']['src']]  # type: Connection
            request['payload']['data'] = csc_symDec_unpickle(client.cipher,
                                                             client.key,
                                                             request['payload']['hmac'],
                                                             request['payload']['data'])

            client.message_history[request['payload']['data']].read()

            newkey, newiv = csc_derive_key(client.key, request['payload']['next-key'])
            client.key = newkey
            client.cipher = csc_generate_symKey(newkey, newiv)
            logging.debug("New derivated key installed")

            return

    def lineToFingerprint(self, pem):
        """
        Transforms an public key in a fingerprint
        :param pem: text to fingerprint
        :return: text of the fingerprint
        """
        key = base64.b64decode(pem.strip().split()[1].encode('ascii'))
        fp_plain = hashlib.md5(key).hexdigest()
        return ':'.join(a + b for a, b in zip(fp_plain[::2], fp_plain[1::2]))

    def printPrompt(self, print_before="", clear=True):
        """
        Prints prompt to the user.
        :param print_before: string to print before printing a new line prompt
        :param clear: to clear or not the current line
        """
        if clear:
            sys.stdout.write("\r")
            for _ in range(128):
                sys.stdout.write(" ")
                sys.stdout.flush()
            sys.stdout.write("\r")

        if len(print_before) > 0:
            sys.stdout.write(print_before + "\n")

        sys.stdout.write('[{}] [{}-{}] '.format(strftime("%H:%M:%S"), self.name, self.id))
        sys.stdout.flush()

    def loop(self):
        while True:
            # sockets to select for reading: (the server socket + user input if any)
            rlist = [self.socket] + [sys.stdin]

            # (check if we have something in queued in bufout to send)
            wlist = [self.socket] if len(self.bufout) > 0 else []

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
                        self.printPrompt()

            # Deal with outgoing data:
            if wlist:
                self.flushout(self.socket)

            # deal with errors
            for s in xl:
                logging.error("EXCEPTION in %s. Closing", s)
                self.socket.close()

    def printHelp(self):
        """
        Prints help to terminal (usually when user inputs a wrong command
        """
        self.printPrompt()
        #print ""
        print "Available commands are:"
        print "list"
        print "help"
        print "history"
        print "whois"
        print ""
        print "Syntax for sending message to 'john':"
        print "john: hello there"
        #print ""
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

        if input == 'history':
            for user in self.connected_clients:
                if len(self.connected_clients[user].message_history) > 0:
                    print "History for " + user + ":"
                    print "{2:<18} {0:<20} {1:<5}".format("Message", "Status", "ID")

                    for id in self.connected_clients[user].message_history:
                        print "{2:<18} {0:<20} {1:<5}".format(
                            str(self.connected_clients[user].message_history[id])[:16],
                            self.connected_clients[user].message_history[id].status,
                            self.connected_clients[user].message_history[id].id)

                    #print ""

            self.printPrompt()
            return

        if input == 'help':
            self.printHelp()
            return

        if input == 'exit' or input == 'quit':
            print "Exiting.."
            self.close()
            exit(0)

        # recognize send a message to someone in the format user: message
        match = re.search(r"(?P<dest>[^:]*):( ?)(?P<message>.+)", input)
        if match:
            dest = match.group("dest")
            message = match.group("message")
            if dest and message:
                self.payload_client_com(dest, message)
                self.printPrompt(clear=True)
                return

        # recognize whois
        match = re.search(r"(?P<whois>[whois]*) +( ?)(?P<user>.+)", input)
        if match:
            whois = match.group("whois")
            user = match.group("user")
            if whois == 'whois' and user:
                self.whois(user)
                self.printPrompt(clear=True)
                return

        # if no command or unrecognized command just print help
        self.printHelp()

    def delClient(self, s, exists=False):
        if exists is True:
            self.printPrompt("Client name already exists. Try again with a different name...")

            print ""

            self.socket = socket(AF_INET, SOCK_STREAM)
            self.start("127.0.0.1", 8080)
        else:
            self.printPrompt("Server down. Exiting...")
            exit(0)


if __name__ == "__main__":
    server_ip = "127.0.0.1"
    server_port = 8080
    cs = ChatSecure()
    try:
        cs.start(server_ip, server_port)
    except KeyboardInterrupt:
        print ""
        print "Exiting..."
        cs.close()