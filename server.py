from socket import *
from threading import Thread
import sys, select
import time
from datetime import datetime, timedelta
# acquire server host and port from command line parameter
if len(sys.argv) != 4:
    print("\n===== Error usage, python3 TCPServer3.py SERVER_PORT BLOCK_DURATION TIMEOUT======\n");
    exit(0);
serverHost = 'localhost'
serverPort = int(sys.argv[1])
block_duration = int(sys.argv[2])
time_out = int(sys.argv[3])
serverAddress = (serverHost, serverPort)

# define socket for the server side and bind address
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(serverAddress)


list_socket = []
users = []
server_start_time = time.time()
def initialise_user():
    with open('credentials.txt', 'r') as f:
        lines = f.readlines()
    for line in lines:
        x = line.split(' ')
        user = {}
        user['username'] = x[0]
        user['unblocked_time'] = 0
        user['logged_in_time'] = 0
        user['last_active'] = 0
        user['is_online'] = bool(False)
        user['blacklist'] = []
        user['socket'] = 0
        user['address'] = 0
        user['offline_message'] = []
        user['p2p_port'] = 0
        users.append(user)
    return

def add_new_user(username, log_time, sockt, address):
    user = {}
    user['username'] = username
    user['unblocked_time'] = 0
    user['logged_in_time'] = log_time
    user['last_active'] = log_time
    user['is_online'] = bool(True)
    user['blacklist'] = []
    user['socket'] = sockt
    user['address'] = address
    user['offline_message'] = []
    user['p2p_port'] = 0
    users.append(user)
    return

class ClientThread(Thread):
    def __init__(self, clientAddress, clientSocket):
        Thread.__init__(self)
        self.clientAddress = clientAddress
        self.clientSocket = clientSocket
        self.clientAlive = True
        
    def run(self):
        message = ''
        user = ''
        while self.clientAlive:
            data = self.clientSocket.recv(1024)
            message = data.decode()
            
            if message == '':
                self.clientAlive = False
                break
            
            if message == 'login':
                user = self.login()

            if message == 'after_log_in':
                self.logging_in(user)
                self.clientAlive = False
                break
    def login(self):
        while self.clientAlive:
            data = self.clientSocket.recv(1024)
            message = data.decode()
            while check_blocked_user(message) or check_online_user(message):

                if check_blocked_user(message):
                    self.clientSocket.send('Blocked'.encode())
                    return
                if check_online_user(message):
                    self.clientSocket.send('Using'.encode())
                    return

                data = self.clientSocket.recv(1024)
                message = data.decode()

            if not check_user(message):
                msg = 'This is a new user. ' 
            else:
                msg = 'Confirmed'
            
            self.clientSocket.send(msg.encode())
            data = self.clientSocket.recv(1024)
            password = data.decode()
            if not check_user(message):
                f = open('credentials.txt', 'a')
                f.write('\n' + message + ' ' + password)
                f.close()
                msg1 = 'Confirmed'

                # add this new user to the profile
                add_new_user(message, int(time.time()), self.clientSocket, self.clientAddress)
            else:
                while not check_password(message, password):
                    msg1 = 'Invalid Password. Please try again'
                    self.clientSocket.send(msg1.encode())
                    data = self.clientSocket.recv(1024)
                    password = data.decode()
                    if password == 'Blocked':
                        curr_time = int(time.time())
                        unblock = curr_time + int(block_duration)

                        block_user(message, int(unblock))
                        return
                msg1 = 'Confirmed'
                login_user(message, self.clientSocket, self.clientAddress)
            self.clientSocket.send(msg1.encode())

            login_notify(message, self.clientSocket)
            return message
    
    def logging_in(self, username):        
            # successfully log in 

            # send timeout to client
            port = self.clientSocket.recv(1024)
            port_num = int(port.decode())
            update_port(username, port_num)
            msg = 'timeout ' + str(time_out)
            self.clientSocket.sendall(msg.encode())
            self.clientSocket.settimeout(time_out)
            try:
                while self.clientAlive:
                    send_offlinemsg(username, self.clientSocket)
                    data = self.clientSocket.recv(1024)
                    message = data.decode()
                    execute = message.split(' ')
                    command = execute[0]
                    if message == '':
                        self.clientAlive = False
                        break 
                    result = ''
                    if message == 'whoelse':
                        result = whoelse(username)
                        self.clientSocket.sendall(result.encode())
                    elif 'whoelsesince' in message:
                        result = whoelsesince(username, execute[1])
                        self.clientSocket.sendall(result.encode())
                    elif 'broadcast' in message:
                        msg_str = 'BROADCAST: '
                        for i in range(1, len(execute)):
                            msg_str += execute[i]
                            if i + 1 != len(execute):
                                msg_str += ' '
                        broadcast(username, msg_str, self.clientSocket)
                    elif 'message' in message:
                        msg_str = ''
                        for i in range(2, len(execute)):
                            msg_str += execute[i]
                            if i + 1 != len(execute):
                                msg_str += ' '
                        sendmessage(username, execute[1], msg_str, self.clientSocket)
                    elif 'block' == command:
                        execute.remove(command)
                        block(username, execute, self.clientSocket)
                    elif 'unblock' == command:
                        execute.remove(command)
                        unblock(username, execute, self.clientSocket)
                    elif 'startprivate' == command:
                        startprivate(username, execute[1], self.clientSocket)
                    elif 'logout' == message:
                        self.clientSocket.sendall('logout'.encode())
                        logout_online_user(username, self.clientSocket)
                        logout_notify(username, self.clientSocket)
                    #self.clientSocket.sendall(result.encode())

            except timeout:
                self.clientSocket.sendall('timeout_logout'.encode())
                time.sleep(1)

                logout_online_user(username, self.clientSocket)
                logout_notify(username, self.clientSocket)
                return

def check_user(username):
    with open('credentials.txt', 'r') as f:
        lines = f.readlines()
    for line in lines:
        x = line.split(' ')
        if x[0] == username:
            return True
    return False

def check_password(username, password):
    with open('credentials.txt', 'r') as f:
        lines = f.readlines()
    for line in lines:
        x = line.split()
        if x[0] == username:
            if x[1] == password:
                return True
            else:
                return False

def check_blocked_user(username):
    for i in range(len(users)):
        if users[i]['username'] != username:
            continue
        curr = int(time.time())

        if curr > users[i]['unblocked_time']:
            users[i]['unblocked_time'] = 0
            return False
        else:
            return True
    return False

def block_user(username, unblock_time):
    for i in range(len(users)):
        if users[i]['username'] != username:
            continue
        users[i]['unblocked_time'] = unblock_time

def check_online_user(username):
    for i in range(len(users)):
        if users[i]['username'] != username:
            continue
        if users[i]['is_online']:
            return True
    return False

def login_user(username, sockt, address):
    for i in range(len(users)):
        if users[i]['username'] != username:
            continue
        users[i]['is_online'] = bool(True)
        users[i]['last_active'] = int(time.time())
        users[i]['socket'] = sockt
        users[i]['address'] = address

def update_port(username, port_num):
    for i in range(len(users)):
        if users[i]['username'] != username:
            continue
        users[i]['p2p_port'] = int(port_num)

def logout_online_user(username, sockt):
    for i in range(len(users)):
        if users[i]['username'] != username:
            continue
        users[i]['is_online'] = bool(False)
        users[i]['last_active'] = int(time.time())
        users[i]['socket'] = 0
        users[i]['address'] = 0

    for i in range(len(list_socket)):
        if list_socket[i]['socket'] == sockt:
            list_socket.remove(list_socket[i])
            return

def login_notify(username, sockt):
    notify = username + ' logged in'
    for i in range(len(users)):
        if users[i]['username'] != username:
            continue 
        # get the user's blacklist
        blacklist = users[i]['blacklist']
        break
    for i in range(len(users)):
        if users[i]['username'] == username:
            continue    
        if users[i]['username'] not in blacklist:
            if users[i]['is_online']:
                users[i]['socket'].send(notify.encode())

def logout_notify(username, sockt):
    notify = username + ' logged out'
    for i in range(len(users)):
        if users[i]['username'] != username:
            continue 
        # get the user's blacklist
        blacklist = users[i]['blacklist']
        break
    for i in range(len(users)):
        if users[i]['username'] == username:
            continue    
        if users[i]['username'] not in blacklist:
            if users[i]['is_online']:
                users[i]['socket'].send(notify.encode())

def whoelse(username):
    names = ''
    for i in range(len(users)):
        if users[i]['username'] == username:
            continue
        blacklist = users[i]['blacklist']
        is_blocked = False
        for j in range(len(blacklist)):
            # if user is in this person's blacklist
            if blacklist[j] == username:
                is_blocked = True
                break
        if not is_blocked:
        
            if users[i]['is_online']: 
                names += users[i]['username']
                names += '\n'
    names = names[:-1]
    return names

def whoelsesince(username, since_last):
    names = ''
    for i in range(len(users)):
        if users[i]['username'] == username:
            continue
        
        # exclude the users blocked this user
        blacklist = users[i]['blacklist']
        is_blocked = False
        for j in range(len(blacklist)):
            if blacklist[j] == username:
                is_blocked = True
                break
        if not is_blocked:
            if users[i]['is_online']:
                names += users[i]['username']
                names += '\n'

            else:
                curr_time = int(time.time())
                past_time = curr_time - int(since_last)


                #  If <time> is greater than the time since 
                # when the server has been running,and the user has logged on
                if server_start_time >= past_time and users[i]['logged_in_time'] != 0:
                    names += users[i]['username']
                    names += '\n'
                elif users[i]['last_active'] >= past_time:
                    names += users[i]['username']
                    names += '\n'

    names = names[:-1]
    return names

def broadcast(username, message, sockt):
    is_blocked = False
    for i in range(len(users)):
        if users[i]['username'] == username:
            continue
        if not users[i]['is_online']:
            continue

        blacklist = users[i]['blacklist']
        if username in blacklist:
            is_blocked = True
        elif users[i]['socket'] != 0: 
                users[i]['socket'].send(message.encode())
    
    # if the user is blocked by another user
    if is_blocked: 
        notify = 'Your message could not be delivered to some recipients'
        sockt.send(notify.encode()) 
    return

def sendmessage(username, receiver, message, sockt):
    sent = False
    for i in range(len(users)):
        if users[i]['username'] != receiver:
            continue

        blacklist = users[i]['blacklist']
        for j in range(len(blacklist)):
            # if user is in receiver's blacklist
            if blacklist[j] == username:
                notify = 'Your message could not be delivered as the recipient has blocked you'
                sockt.send(notify.encode())
                return 

        format_msg = username + ': ' + message
        # send immediately if online
        if users[i]['is_online']:
            users[i]['socket'].send(format_msg.encode())
            sent = True
            # else, save msg to offline message
        else:
            users[i]['offline_message'].append(format_msg)
            sent = True
    
    # if the message cannot be processed
    if sent == False:
        notify = 'Your message could not be delivered as the user does not exist'
        sockt.send(notify.encode())

def send_offlinemsg(username, sockt):
    for i in range(len(users)):
        if users[i]['username'] != username:
            continue
        # no offline message
        if len(users[i]['offline_message']) == 0:
            return 
        for j in range(len(users[i]['offline_message'])):
            msg = users[i]['offline_message'][j]
            sockt.sendall(msg.encode())
            users[i]['offline_message'] = []

def block(username, block_users, sockt):
    if username in block_users:
        sockt.sendall('You cannot block yourself.'.encode())
        return
    is_done = False
    for i in range(len(users)):
        if users[i]['username'] != username:
            continue
        num_blocked = 0
        for j in range(len(block_users)):

            # check if this user exists
            for k in range(len(users)):
                if block_users[j] == users[k]['username']:
                    users[i]['blacklist'].append(block_users[j])
                    num_blocked += 1
        if num_blocked == len(block_users):
            is_done = True
    if is_done:
        if len(block_users) == 1:
            sockt.sendall('You block the user.'.encode())
        else:
            sockt.sendall('You block the users.'.encode())
    else:
        sockt.sendall('The user does not exist'.encode())

def unblock(username, block_users, sockt):
    is_done = False
    for i in range(len(users)):
        if users[i]['username'] != username:
            continue
        num_blocked = 0
        for j in range(len(block_users)):
            for k in range(len(users)):
                if block_users[j] == users[k]['username']:
                    users[i]['blacklist'].remove(block_users[j])
                    is_done = True
    if is_done:
        if len(block_users) == 1:
            sockt.sendall('You unblock the user.'.encode())
        else:
            sockt.sendall('You unblock the users.'.encode())
    else:
        sockt.sendall('The use does not exist/ You did not block the user'.encode())

def startprivate(username, user, sockt):
    is_valid = False
    if user == username:
        sockt.sendall('You cannot startprivate with yourself'.encode())
        return
    for i in range(len(users)):
        if users[i]['username'] != user:
            continue

        for j in range(len(users[i]['blacklist'])):
            if users[i]['blacklist'][j] == username:
                sockt.sendall('The user has blocked you'.encode())
                return
        if not users[i]['is_online']:
            sockt.sendall('The user is currently offline'.encode())
            return
        else:
            is_valid = True
            user_sockt = users[i]['socket']
            request = username + ' would like to private message, enter y or n: '
            users[i]['socket'].send(request.encode())
            answer = user_sockt.recv(1024)

            if answer.decode() == 'y':
                server_port = str(helper_startprivate(username))
                message = username + 'p2p server address: ' + server_port
                users[i]['socket'].sendall(message.encode())
                response = users[i]['username'] + ' accepts private message'
                sockt.sendall(response.encode())

            elif answer.decode() == 'n':
                response = users[i]['username'] + ' declines private message'
                sockt.sendall(response.encode())
                users[i]['socket'].sendall('You declined the request'.encode())
    if is_valid == False:
        sockt.sendall('The username is invalid'.encode())
# get the user's p2p port number
def helper_startprivate(username):
    for i in range(len(users)):
        if users[i]['username'] != username:
            continue
        return users[i]['p2p_port']
initialise_user()
while True:
    serverSocket.listen()
    clientSockt, clientAddress = serverSocket.accept()
    new_socket = {}
    new_socket['socket'] = clientSockt
    new_socket['address'] = clientAddress
    list_socket.append(new_socket)
    clientThread = ClientThread(clientAddress, clientSockt)
    clientThread.start()
serverSockt.close()
