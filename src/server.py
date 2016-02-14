#!/usr/bin/env python3

import json
import message
import reseau
import signal
import socket
import sys
from threading import Thread

class ListenerClient(Thread):
	def __init__(self, sock, sockets, cles_publiques):
		Thread.__init__(self)
		self.sock = reseau.MySocket(sock)
		self.sockets = sockets
		self.cles_publiques = cles_publiques
		self.identifiant = ''
		print('Un client vient de se connecter.')

	def run(self):
		try:
			while True:
				message_brut = self.sock.next_message()
				message = json.loads(message_brut)
				if message['type_msg'] == 'identification':
					# Un client s'identifie.
					# On lui envoie la liste des clients connectés.
					self.sock.envoyer_message('msg_serveur', '', [self.identifiant], self.cles_publiques)
					# On l'ajoute à la liste des clients connectés
					self.identifiant = message['emetteur']
					self.sockets[self.identifiant] = self.sock
					self.cles_publiques[self.identifiant] = message['content']
					# On informe les autres clients qu'un nouveau client s'est connecté.
					for client in self.sockets.values():
						client.envoyer_message('nv_client', '', [self.identifiant], {'id': self.identifiant, 'clé' : self.cles_publiques[self.identifiant]})
					print(self.identifiant + ' s\'est identifié.')
				elif message['type_msg'] in ['message','demande_auth_1','demande_auth_2','demande_auth_3']:
					for destinataire in message['destinataires']:
						s = self.sockets[destinataire]
						s.envoyer_message_brut(message_brut)
				else:
					print("Réception d'un message de type non reconnu")
		except ConnectionResetError:
			# La connexion a été fermée par le client.
			# On supprime le client de la liste des clients connectés.
			del self.sockets[self.identifiant]
			del self.cles_publiques[self.identifiant]
			print(self.identifiant, 's\'est déconnecté')
		except OSError:
			pass
			#print("fin thread")

	def fermer(self):
		#print("fermeture thread")
		self.sock.close()
		#self.exit()


class Serveur():
	def __init__(self):
		self.client_connect=[]
		self.cles_publiques = {}
		self.sockets = {}
		self.sock = socket.socket()

	def fermer(self, signum, frame):
		print('Serveur fermé')
		for t in self.client_connect:
			t.fermer()
		self.sock.shutdown(socket.SHUT_RDWR)
		self.sock.close()
		exit()

	def attendre_client(self):
		signal.signal(signal.SIGINT, self.fermer)
		#signal.signal(signal.SIGABRT, self.fermer)
		host = socket.gethostname()
		port = 12345
		self.sock.bind((host, port))
		self.sock.listen(5)
		print('Serveur initialisé')
		print(socket.gethostbyname(host))
		while True:
			so, ad = self.sock.accept()
			t = ListenerClient(so, self.sockets, self.cles_publiques)
			t.start()
			self.client_connect.append(t)



try:
	serveur=Serveur()
	serveur.attendre_client()
except KeyboardInterrupt:
	sys.exit(0)
