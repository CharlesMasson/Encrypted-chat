#!/usr/bin/env python3
# -*- coding: utf8 -*-

import sys
import socket
from threading import Thread
#import readline # better input
import reseau

class User:
	def __init__(self, id_user, host, port, private_key, public_key):
		self.id = id_user
		self.socket = reseau.MySocket()
		
		self.socket.connect((host, port)) #envoi d'une demande de connexion au serveur
		#On envoie des infos au serveur:
		self.socket.envoyer_message('identification', id_user, [], public_key)
		
		print(self.socket.next_message())
		
		



user=User('Bob', '192.168.56.1', 12345, '123','97987987')


