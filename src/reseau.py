#!/usr/bin/env python3
# -*- coding: utf8 -*-

import re
import json
import socket

class MySocketClosed(Exception):
	pass

class MySocket():
	def __init__(self, socket = socket.socket()):
		self.socket = socket
		self.buffer = b''
		self.to_stop = False
	
	def connect(self, a):
		self.socket.connect(a)
		self.socket.settimeout(1)
	
	def envoyer_message_brut(self, message):
		self.socket.send((str(len(message)) + '\n' + message).encode())

	def envoyer_message(self, type_msg, emetteur, destinataires, content):
		result = {}
		result['emetteur'] = emetteur
		result['destinataires'] = destinataires
		result['type_msg'] = type_msg
		result['content'] = content	
		self.envoyer_message_brut(json.dumps(result))

	def next_message(self):
		"""Écoute l'interlocuteur jusqu'à ce qu'un message complet soit reçu.
		Renvoie le message complet."""
		taille_attendue = -1
		while True:
			if taille_attendue == -1:
				# si la taille du prochain message n'a pas encore été calculée
				x = re.findall(b'^([0-9]*)\n(.*)$', self.buffer)
				if len(x) == 1:
					n, m = x[0]
					taille_attendue = int(n)
					self.buffer = m
			if taille_attendue != -1 and len(self.buffer) >= taille_attendue:
				message = self.buffer[:taille_attendue]
				self.buffer = self.buffer[taille_attendue:]
				return message.decode()
			while True:
				try:
					data = self.socket.recv(1024)
				except socket.timeout:
					#print('timeout loop')
					continue
				if data == b'':
					self.close()
					raise MySocketClosed()
				else:
					#print('data received')
					break
			self.buffer += data
	
	def next_message_decode(self):
		return json.loads(self.next_message())

	def close(self):
		#print('MySocket closed')
		self.socket.shutdown(socket.SHUT_RDWR)
		self.socket.close()

