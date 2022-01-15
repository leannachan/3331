from socket import *
import sys
import select
from threading import Thread, Timer
import queue
import time
import os
#Server would be running on the same host as Client
if len(sys.argv) != 2:
    print("\n===== Error usage, python3 Client.py SERVER_PORT ======\n");
    exit(0);
server_port = int(sys.argv[1])
serverHost = 'localhost'
serverAddress = (serverHost, server_port)

# define a socket for the client side, it would be used to communicate with the server
clientSocket = socket(AF_INET, SOCK_STREAM)
global is_private
is_private = None
global is_asked_private_request 
is_asked_private_request = None
def receive():
    global is_private
    global is_asked_private_request
    global p2p_clientSocket
    global p2p_client
    global p2p_server
    result = clientSocket.recv(1024)

    while result.decode() != 'timeout_logout' and result.decode() != 'logout':
        if 'accepts private message' in result.decode():
            print(result.decode())
            command = result.decode().split(' ')
            username = command[0]
            p2p_clientSocket, p2p_clientAddress = p2pSocket.accept()
            p2p_client['socket'] = p2p_clientSocket
            p2p_client['address'] = p2p_clientAddress
            p2p_client['username'] = username
            is_private = True
            th1 = Thread(target=p2p_receive,args=[p2p_clientSocket])
            th1.start()
        elif ' would like to private message, enter y or n: ' in result.decode():
            print(result.decode())
            is_asked_private_request = True

        elif 'p2p server address: ' in result.decode():
            message = result.decode().split(': ')
            port_num = message[1]

            name = result.decode().split(' ')
            username = name[0]
            server_address = (serverHost, int(port_num))
            p2p_clientSocket = socket(AF_INET, SOCK_STREAM)
            p2p_clientSocket.connect(server_address)
            p2p_server['socket'] = p2p_clientSocket
            p2p_server['address'] = server_address
            p2p_server['username'] = username
            is_private = True
        elif result.decode() != '' and result.decode() != ' ':
            print(result.decode())
        result = clientSocket.recv(1024)
    try:
        p2p_client['socket'].send('logout'.encode())
        time.sleep(1)
        p2p_client['socket'].shutdown(SHUT_RDWR)
        p2p_client['socket'].close()
        p2p_client = {}
    except:
        try:
            p2p_server['socket'].send('logout'.encode())
            time.sleep(1)
            p2p_server['socket'].shutdown(SHUT_RDWR)
            p2p_server['socket'].close()
            p2p_server = {}
        except:
            pass
    os._exit(1)

def p2p_receive(sockt):
    try:
        result = sockt.recv(1024)
        #print('result:', result)
        while result.decode() != 'The user stopped your private session' and result.decode() != 'logout':
            if result.decode() != '' and result.decode() != ' ':
                print(result.decode())
            result = sockt.recv(1024)
        if result.decode() == 'The user stopped your private session':
            print(result.decode())
        sockt.shutdown(SHUT_RDWR)
        sockt.close()
        p2p_client = {}
        p2p_server = {}
        global is_private
        if result.decode() != 'logout':
            is_private = False
        #os._exit(1)
    except:
        pass

# build connection with the server and send message to it
clientSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
clientSocket.connect(serverAddress)
clientSocket.setblocking(True)

p2pSocket = socket(AF_INET, SOCK_STREAM)
p2pSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
new_server_port = server_port + 1
is_bind = False
while (is_bind == False):
    try:
        if p2pSocket.bind((serverHost, new_server_port)) == None:
            is_bind = True
    except error as msg:
        new_server_port += 1
        is_bind == True

p2pSocket.listen()

global p2p_clientSocket
p2p_clientSocket = None
list_socket = [clientSocket, p2pSocket]
p2p_server = {}
p2p_client = {}
clientSocket.sendall('login'.encode())
global username

while True: 
    username = input('Username: ')
    clientSocket.sendall(username.encode())
    result = clientSocket.recv(1024)
    if result.decode() == 'Blocked':
        print('Your account is blocked due to multiple login failures. Please try again later')
        clientSocket.shutdown(SHUT_RDWR)
        clientSocket.close()
        sys.exit(1)
    elif result.decode() == 'Using':
        print('This account is already being used by other client. Please enter another username')
        clientSocket.sendall('login'.encode())
        continue
    elif result.decode() == 'Invalid Password. Please try again':
        print(result.decode(), end='')
    password = input('Password: ')
    clientSocket.sendall(password.encode())
    result = clientSocket.recv(1024)
    attempt = 1
    while result.decode() != 'Confirmed':
        # 3 attempts of unsuccessful login
        if attempt == 3:
            clientSocket.sendall('Blocked'.encode())
            clientSocket.shutdown(SHUT_RDWR)
            clientSocket.close()
            print('Invalid Password. Your account has been blocked. Please try again later')
            sys.exit(1)
        print(result.decode())
        password = input('Password: ')
        clientSocket.sendall(password.encode())
        result = clientSocket.recv(1024)
        attempt += 1
    print('Welcome to the greatest messaging application ever!')
    clientSocket.sendall('after_log_in'.encode())
    
    clientSocket.sendall(str(new_server_port).encode())
    result = clientSocket.recv(1024)

    if 'timeout' in result.decode():
        string = result.decode().split(' ')
        time_out = int(string[1])

    th1 = Timer(2, receive)
    th1.start()
    sockt = clientSocket
    while True:
        th1 = Timer(1, receive)
        th1.start()

        command = input()
        split_command = command.split(' ')
        valid_command = split_command[0]
        if command == 'whoelse':
            sockt.sendall('whoelse'.encode())
        elif 'whoelsesince' in command:
            sockt.sendall(command.encode())
        elif 'broadcast' in command:
            sockt.sendall(command.encode())
        elif 'message' in command:
            sockt.sendall(command.encode())
        elif 'unblock' in command:
            sockt.sendall(command.encode())
        elif 'block' in command:
            sockt.sendall(command.encode())
        elif 'startprivate' in command:
            sockt.sendall(command.encode())
            #is_private = True
        elif 'private' == valid_command:
            sockt.sendall('p2p'.encode())
            if is_private != True:
                print('You did not startprivate')
                continue
            try:
                if split_command[1] != p2p_client['username']:
                    print('The username is invalid')
                    continue
            except:
                try:
                    if split_command[1] != p2p_server['username']:
                        print('The username is invalid')
                        continue
                except:
                    pass
            message = username + ' (private): '
            for i in range(2, len(split_command)):
                message += split_command[i]
                if i - 1 != len(split_command):
                    message += ' '
            try:
                p2p_client['socket'].sendall(message.encode())
            except:
                try:
                    p2p_server['socket'].sendall(message.encode())
                except:
                    print('The user is no longer online at the port')
        elif is_asked_private_request == True and 'y' == command:
            sockt.sendall(command.encode())
            is_asked_private_request = False
            time.sleep(1)
            pass_socket = None
            if p2p_server != {}:
                pass_socket = p2p_server['socket']
            th2 = Timer(1, p2p_receive, [pass_socket])
            th2.start()

        elif is_asked_private_request == True and 'n' == command:
            sockt.sendall(command.encode())
            is_asked_private_request = False
        elif 'stopprivate' == valid_command:
            sockt.sendall('p2p'.encode())
            try:
                if split_command[1] != p2p_client['username']:
                    print('The username is invalid')
                    continue
            except:
                try:
                    if split_command[1] != p2p_server['username']:
                        print('The username is invalid')
                        continue
                except:
                    pass
            if not is_private:
                print('There does not exist an active p2p messaging session')
            else:
                message = 'The user stopped your private session'
                try:
                    p2p_client['socket'].send(message.encode())
                    p2p_client['socket'].shutdown(SHUT_RDWR)
                    p2p_client['socket'].close()
                    p2p_client = {}
                except:
                    try:
                        p2p_server['socket'].send(message.encode())
                        p2p_server['socket'].shutdown(SHUT_RDWR)
                        p2p_server['socket'].close()
                        p2p_server = {}
                    except:
                        print('The user is no longer online at the port')
                is_private = False
        elif 'logout' == command:
            '''
            try:
                p2p_client['socket'].send('logout'.encode())
                time.sleep(1)
                p2p_client['socket'].shutdown(SHUT_RDWR)
                p2p_client['socket'].close()
                p2p_client = {}
            except:
                try:
                    p2p_server['socket'].send('logout'.encode())
                    time.sleep(1)
                    p2p_server['socket'].shutdown(SHUT_RDWR)
                    p2p_server['socket'].close()
                    p2p_server = {}
                except:
                    pass
            '''
            sockt.sendall('logout'.encode())
            clientSocket.close()
            #os._exit(1)
        else:
            print('Error. Invalid command')

        pass_socket = None
        if p2p_client != {}:
            pass_socket = p2p_client['socket']
        elif p2p_server != {}:
            pass_socket = p2p_server['socket']
        th2 = Timer(1, p2p_receive, [pass_socket])
        th2.start()

clientSocket.close()
