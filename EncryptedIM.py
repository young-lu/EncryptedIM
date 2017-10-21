import socket
import select
import sys
import argparse
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto import Random

parser = argparse.ArgumentParser()
parser.add_argument("--s", dest='serverStatus',
                    action='store_true', default=False)
parser.add_argument("--c", dest='host')
parser.add_argument("--confKey", dest='conf', help='confidentiality key')
parser.add_argument("--authKey", dest='auth', help='authenticity key')
args = parser.parse_args()


HOST = ''
SOCKETS = []
RECV_BUFFER = 4096
PORT = 9999

BLOCK_SIZE=16

def pad(s) :
	return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

def unpad(s) :
	return s[0:-ord(s[-1])]


def encrypt(secret, data):
    """encrypt the message passed in data using the key passed in secret"""

    #generate an hmac from the authkey
    auth = SHA256.new(args.auth).hexdigest()
    h = HMAC.new(auth, digestmod=SHA256).hexdigest()  

    #create key from confkey and random iv
    key = (SHA256.new(secret).hexdigest())[:BLOCK_SIZE]
    iv = Random.new().read(AES.block_size)

    #create encryptor object
    encryptor = AES.new(key, AES.MODE_CBC, iv)

    #pad message, concatenate with hmac, adn encrypt
    padding = pad(data)
    plaintext = h + padding
    cyphertext = encryptor.encrypt(plaintext)

    #send iv in clear with cyphertext
    sendMe = iv + cyphertext
    return sendMe


def decrypt(secret, data):
    """decrypt message passed in data with key passed in secret"""

    #generate hmac for verification 
    auth = SHA256.new(args.auth).hexdigest()

    #get iv from message and hash confkey 
    key = (SHA256.new(secret).hexdigest())[:BLOCK_SIZE]
    iv = data[:BLOCK_SIZE]

    #create decryptor object with confkey and iv, decrypt
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    hashAndMsg = data[BLOCK_SIZE:]
    dcryptd = decryptor.decrypt(hashAndMsg)

    # verify HMAC
    myHash = HMAC.new(auth, digestmod=SHA256).hexdigest()
    h = dcryptd[:64]
    if (h == myHash):
        msg = dcryptd[64:]
        msg = unpad(msg)
        return msg
    else:
        sys.stdout.write('HMAC verification failed.')
        sys.exit(0)

# this function does most of the work, it loops with select.select()
# to constantly listen for incoming messages and send outgoing


def listen(con):
    listen_list = [sys.stdin, con]

    sys.stdout.write('')
    sys.stdout.flush()

    while 1:
        readable, writable, exceptional = select.select(
            listen_list, [], [], 0.0)

        for s in readable:
            if s == con:
                datum = con.recv(RECV_BUFFER)

                if datum:
                    sys.stdout.write(decrypt(args.conf, datum))
                    sys.stdout.write('')
                    sys.stdout.flush()
                else:
                    sys.exit()
            else:
                msg = sys.stdin.readline()

                if len(msg) > 0 and msg != " ":
                    con.send(encrypt(args.conf, msg))
                    sys.stdout.write('')
                    sys.stdout.flush()


def IMServer():
    """server class using sockets, select"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    SOCKETS.append(server_socket)

    connection, addr = server_socket.accept()

    try:
        listen(connection)

    except KeyboardInterrupt:
        server_socket.close()
        sys.exit()


def IMClient():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(2)

    client_socket.connect((HOST, PORT))

    try:
        listen(client_socket)

    except KeyboardInterrupt:
        client_socket.close()
        sys.exit()


if __name__ == "__main__":

    if not args.conf or not args.auth:
        print "necessary confidentiality/authorization keys not provided..."

    elif not args.serverStatus and not args.host:
        print 'incorect arguments, must provide hostname'

    elif (args.serverStatus):
        print("authkey: " + args.auth)
        print('confkey: ' + args.conf)
        IMServer()

    elif (args.host != 'no host name provided'):
        print("authkey: " + args.auth)
        print('confkey: ' + args.conf)
        HOST = args.host
        IMClient()

    else:
        print('incorrect arguments, please try again...\n')

print('\n')
