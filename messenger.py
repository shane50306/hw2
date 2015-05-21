#new user
#talk_group
#all on-line user
#avoid duplicate login


import socket
import struct
from getpass import getpass
from argparse import ArgumentParser
import threading
import time

header_struct = struct.Struct('!I')  # messages up to 2**32 - 1 in length

def recvall(sock, length):
	blocks = []
	while length:
		block = sock.recv(length)
		if not block:
			raise EOFError('socket closed with ', length, ' bytes left in this block')
		length -= len(block)
		blocks.append(block)
	return b''.join(blocks)

def get_block(sock):
	data = recvall(sock, header_struct.size)
	(block_length,) = header_struct.unpack(data)
	return recvall(sock, block_length).decode("utf-8")

def put_block(sock, message):
	message = str.encode(message)
	block_length = len(message)
	sock.send(header_struct.pack(block_length))
	sock.send(message)

	
	
	
def server(address, port):
	user_list = {'Shane':'123456', 'Tom':'123456', 'John':'123456', "Smith":"123456", "Nick":"123456"}
	on_line_list = []
	lock = {'on_line_list':threading.Lock(), 'Shane':threading.Lock(), 'Tom':threading.Lock(), 'John':threading.Lock(), "Smith":threading.Lock(), "Nick":threading.Lock()}
	message_queue = {'Shane':[], 'Tom':[], 'John':[], "Smith":[], "Nick":[]}

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind((address, port))
	sock.listen(5)
	print('Server is ready!')
	
	while True:
		sc, sockname = sock.accept()
		t = threading.Thread(target=server_client, args=(sc, user_list, on_line_list, message_queue, lock))
		t.start()
		print('Accepted connection from', sockname)
	
	sock.close()

def server_client(sc, user_list, on_line_list, message_queue, lock):
	
	try:
		while True:
			account = get_block(sc)
			if account == 'new':
				account = server_new_user(sc, user_list, on_line_list, message_queue, lock)
				print("New user: ", account, "is on-line")
				break				
			password = get_block(sc)
			if account in user_list:
				lock['on_line_list'].acquire()
				if account in on_line_list:
					put_block(sc, 'bad')
				elif user_list[account] == password:
					put_block(sc, 'good')
					print(account, "is on-line")
					on_line_list.append(account)
					lock['on_line_list'].release()
					break
				else:
					put_block(sc, 'bad')
				lock['on_line_list'].release()
			else:
				put_block(sc, 'bad')
	except:
		sc.close()
		return
		
	try:
		while True:
			command = get_block(sc)
			if command == 'see':
				server_see(sc, account, message_queue, lock)
			elif command == 'all_user':
				server_list_all_user(sc, user_list, on_line_list)
			elif command == 'user':
				server_list_user(sc, user_list, on_line_list)
			elif command == 'talk':
				server_talk(sc, account, message_queue, lock)
			elif command == 'send':
				server_send(sc, account, message_queue, lock)			
			elif command == 'broadcast':
				server_broadcast(sc, account, on_line_list, message_queue, lock)
			elif command == 'logout':
				server_logout(account, on_line_list, lock)
				print(account, "is off-line")
				break
	except:
		print(account, "is off-line")
		server_logout(account, on_line_list, lock)
		sc.close()
	sc.close()

def server_new_user(sock, user_list, on_line_list, message_queue, lock):
	
	while True:
		account = get_block(sock)
		password = get_block(sock)
		
		if account in user_list:
			put_block(sock, 'bad account')
		else:
			lock[account] = threading.Lock()
			message_queue[account] = []
			user_list[account] = password
			lock['on_line_list'].acquire()
			on_line_list.append(account)
			lock['on_line_list'].release()
			put_block(sock, 'ok')
			return account
			
			
	
def server_see(sock, account,  message_queue, lock):
	lock[account].acquire()
	for message in message_queue[account]:
		for name, mess in message.items():
			temp = name + '-> ' + mess
			put_block(sock, temp)
	message_queue[account] = []
	lock[account].release()
	put_block(sock, '')
	
def server_list_all_user(sock, user_list, on_line_list):
	for user in user_list:
		if user in on_line_list:
			message = user + "\ton-line"
		else:
			message = user + "\toff-line"
		put_block(sock, message)
	put_block(sock, '')

def server_list_user(sock, user_list, on_line_list):
	for user in on_line_list:
		message = user + "\ton-line"
		put_block(sock, message)
	put_block(sock, '')	
	
def server_talk(sock, myaccount, message_queue, lock):
	
	account = get_block(sock)
	if not account in message_queue:
		put_block(sock, "bad account")
		return
	else:
		put_block(sock, "ok")
		
	while True:
		message = get_block(sock)
		if not message:
				break
		elif message == '!see!':
			server_see(sock, myaccount,  message_queue, lock)
			continue
		lock[account].acquire()
		message_queue[account].append({myaccount:message})
		lock[account].release()
	
def server_send(sock, myaccount, message_queue, lock):
	account = get_block(sock)
	message = get_block(sock)
	
	if not account in message_queue:
		put_block(sock, "bad account")
	else:
		lock[account].acquire()
		message_queue[account].append({myaccount:message})
		lock[account].release()
		put_block(sock, "send ok")
	
def server_broadcast(sock, myaccount, on_line_list, message_queue, lock):
	message = get_block(sock)
	
	for account in on_line_list:
		lock[account].acquire()
		message_queue[account].append({myaccount:message})
		lock[account].release()
	
def server_logout(account, on_line_list, lock):
	lock['on_line_list'].acquire()
	on_line_list.remove(account)
	lock['on_line_list'].release()
	
	

def client(address, port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((address, port))
	
	login(sock)
	print("Welcome to Messenger")
	print("\nPlease type:\n'see' for see your message\n'user' for list all on-line users\n'all_user' for list all users\n'talk name' for talk to someone with a conversation\n'talk_group name1 name2 ...' for talk to some people with a conversation\n'send name message' to direct send a message to someone\n'broadcast message' for broadcast to all on-line users\n'logout' for log out\n'help' for help")
	while True:
		command = input('> ')
		if len(command) == 0:
			client_see(sock)
			continue
		elif command.split()[0] == 'see':
			client_see(sock)
			continue
		elif command.split()[0] == 'all_user':
			client_list_all_user(sock)
		elif command.split()[0] == 'user':
			client_list_user(sock)
		elif command.split()[0] == 'talk':
			client_talk(sock, command.split()[1])
			continue
		elif command.split()[0] == 'talk_group':
			client_talk_group(sock, command[11:])
			continue
		elif command.split()[0] == 'send':
			client_send(sock, command[5:])	
		elif command.split()[0] == 'broadcast':
			client_broadcast(sock, command[10:])
		elif command.split()[0] == 'logout':
			client_logout(sock)
			print("Bye~")
			break
		elif command.split()[0] == 'help':
			print("\nPlease type:\n'see' for see your message\n'user' for list all users\n'all_user' for list all users\n'talk name' for talk to someone with a conversation\n'talk_group name1 name2 ...' for talk to some people with a conversation\n'send name message' to direct send a message to someone\n'broadcast message' for broadcast to all on-line users\n'logout' for log out\n'help' for help")
		else:
			print("Wrong input, please try again!")
		client_see(sock)
	
	sock.close()

def login(sock):
	while True:
		account = input("Account: ")
		if account == 'new':
			client_new_user(sock)
			break
			
		password = getpass()
		
		put_block(sock, account)
		put_block(sock, password)
		
		response = get_block(sock)
		if response == 'good':
			break
		else:
			print('Error account or password, or duplicate login, please try again!')

def client_new_user(sock):
	put_block(sock, 'new')
	
	while True:
		account = input("Account: ")
		password = getpass()
		
		put_block(sock, account)
		put_block(sock, password)
		
		message = get_block(sock)
		if message == 'ok':
			break
		else:
			print('Please try a different account!')
			
def client_see(sock):
	put_block(sock, 'see')
	while True:
			message = get_block(sock)
			if not message:
				break
			print(message)

def client_list_all_user(sock):
	put_block(sock, 'all_user')
	while True:
			user_statue = get_block(sock)
			if not user_statue:
				break
			print(user_statue)

def client_list_user(sock):
	put_block(sock, 'user')
	while True:
			user_statue = get_block(sock)
			if not user_statue:
				break
			print(user_statue)			

def client_talk_group(sock, account):
	account_list = account.split()
	
	try:
		while True:
			message = input('You-> ')
			if len(message) == 0:
				client_see(sock)
				continue

			for user in account_list:
				put_block(sock, 'send')
				put_block(sock, user)
				put_block(sock, message)
				status = get_block(sock)
				if status == 'bad account':
					print("Bad account: ", user)
					account_list.remove(user)
				
			client_see(sock)
				
	except KeyboardInterrupt:
		put_block(sock, '')
		print('\nexit')
				
def client_talk(sock, account):
	put_block(sock, 'talk')
	put_block(sock, account)
	
	message =  get_block(sock)
	if message == 'bad account':
		print(message)
		return
	
	try:
		while True:
			message = input('You-> ')
			if len(message) == 0:
				put_block(sock, '!see!')
				while True:
					message = get_block(sock)
					if not message:
						break
					print(message)
				continue

			put_block(sock, message)
			
			put_block(sock, '!see!')
			while True:
				message = get_block(sock)
				if not message:
					break
				print(message)
				
	except KeyboardInterrupt:
		put_block(sock, '')
		print('\nexit')
		
def client_send(sock, command):
	account = command.split()[0]
	message = command[len(account)+1:]
	
	put_block(sock, 'send')
	put_block(sock, account)
	put_block(sock, message)
	
	status = get_block(sock)
	print(status)
	
def client_broadcast(sock, message):
	put_block(sock, 'broadcast')
	put_block(sock, message)

def client_logout(sock):
	put_block(sock, 'logout')

	
if __name__ == '__main__':

	choices = {'client' : client, 'server' : server}
	#serverName = '140.123.101.235'
	serverName = '127.0.0.1'
	serverPort = 12000
	
	parser = ArgumentParser(description='Messenger')
	parser.add_argument('role', choices=choices, help='which role to play')
	args = parser.parse_args()
	
	function = choices[args.role]
	function(serverName, serverPort)
	