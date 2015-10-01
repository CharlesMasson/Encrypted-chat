#!/usr/bin/env python3
# -*- coding: utf8 -*-

import sys
import socket
from threading import Thread
import readline # better input
import json
import Crypto
import Crypto.Random.random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import reseau
import hashlib
import binascii
import time
import Cryptographie as c
import fileinput
import os

def byteToHex(byte):
	return binascii.b2a_hex(byte).decode('ASCII')
	
def hexToByte(hex_str):
	return binascii.a2b_hex(hex_str.encode('ASCII'))

def save_public_keys(keys, fname):
	jkeys={}
	for user, rsa in keys.items():
		jkeys[user]={'n':rsa.n, 'e':rsa.e}
	f=open(fname, 'w')
	f.write(json.dumps(jkeys))
	f.close()

class Sender(Thread):
	def __init__(self, socket, id_user, private_key, public_keys, keys_msg, incr_msg,temp):
		Thread.__init__(self)
		self.socket=socket
		self.id_user=id_user
		self.private_key=private_key
		self.public_keys=public_keys
		self.keys_msg=keys_msg
		self.incr_msg=incr_msg
		self.temp=temp
	
	def run(self):

		while True:
			m = input("> ")
			if(m!=""):
				action=m[0] #On récupère le type de l'action à réaliser:
			
				if action=="?":
					#On effectue la 1ère étape du protocole d'authentification:
					destinataire=m[1:] #On récupère le destinataire
					
					try:
						n = Crypto.Random.random.getrandbits(128) #On génère un n aléatoire
						messageAB = n.to_bytes(16, byteorder='big')
						#on va le chiffrer avec la clé publique de B
						cipher = PKCS1_OAEP.new(self.public_keys[destinataire])
						n2 = cipher.encrypt(messageAB)
					
						In2=byteToHex(n2)
					
						#On stocke dans le fichier temporaire le n choisit
						self.temp[destinataire]={}
						self.temp[destinataire]["n_perso"]=n
					
						content={} 
						content["n2"]=In2
						self.socket.envoyer_message('demande_auth_1', self.id_user, [destinataire], content)
					
						print("Demande d'authentification envoyée")
					except KeyError:
						print("Cette personne n'est pas connectée ...")

				elif action=="&":
					#acceptation de la demande d'authentification de qqn
					type_msg="accept"
					user_asking=m[1:]
					
					try:
						cipher = PKCS1_OAEP.new(self.private_key)
						message = cipher.decrypt(self.temp[user_asking]["n2"])
						Dn_A = int.from_bytes(message, byteorder='big')

						#on génère n_B et on le chiffre
						n_B= Crypto.Random.random.getrandbits(128)
						#on va caster n_B en une suite de bits
						messageBA = n_B.to_bytes(16, byteorder='big')
						#on va le chiffrer avec la clé publique de A cette fois
						cipher = PKCS1_OAEP.new(self.public_keys[user_asking])
						n2_B = cipher.encrypt(messageBA)
						In2_B=byteToHex(n2_B)
						#calcul du hash de (n_A;n_B) mais ici Dn_A
						#on va caster (Dn_A:n_B) en entiers
						h = SHA256.new()
						h.update("{0}:{1}".format(Dn_A, n_B).encode('ASCII'))
						l_B = h.hexdigest()
				
						#On stocke dans le fichier temporaire Dn_A et n_B
						self.temp[user_asking]["n_demandeur"]=Dn_A
						self.temp[user_asking]["n_perso"]=n_B

						content={}
						content["n2_2"]=In2_B
						content["l"]=l_B
				
						#On envoie à l'utilisateur demandant l'authentification B, nB' et lB (voir schéma authentification)
						self.socket.envoyer_message('demande_auth_2', self.id_user, [user_asking], content)
					
						print("J'accepte l'authentification de "+user_asking)
					except KeyError:
						print("Cette personne ne vous a pas envoyé une demande d'authentification ...")
				else:
					type_msg="message"
					#envoi d'un message à qqn
					m_parts=m.split(':')
					#On récupère les destinataires
					dest=m_parts[0]
					destinataires=dest.split(',') #On crée la liste des destinataires du message
					
					try:
						keys={}
						for user in destinataires:
							keys[user]={}
							keys[user]['ksd'] = self.keys_msg[user]['ksd']
							keys[user]['kds'] = self.keys_msg[user]['kds']

						#On récupère le contenu du message
						message=m_parts[1]
						#On chiffre le message
						self.incr_msg=self.incr_msg+1
						msg_chiffre, cles, resumes = c.pret_a_envoyer(message, keys, self.incr_msg)
					
						#On met toutes les infos necessaires dans du json
						content={}
						content["message"]=byteToHex(msg_chiffre) #Le message chiffré
						content["incr"]=self.incr_msg
						for user in destinataires:
							content[user]={}
							content[user]["k"]=byteToHex(cles[user]) #La clé k encryptée avec la clé de communication
							content[user]["r"]=byteToHex(resumes[user]) #Le résumé r pour l'intégrité
					
						#On transpose notre dictionnaire au format json
						self.socket.envoyer_message('message', self.id_user, destinataires, content)
					except KeyError:
						print("Un des destinataires rentrés n'existe pas ! Vérifiez que vous vous êtes bien authentifié avec lui")

class Receiver(Thread):
	def __init__(self,socket,id_user, private_key, public_keys, keys_msg, incr_msg,temp):
		Thread.__init__(self)
		self.socket=socket		
		self.id_user=id_user
		self.private_key=private_key
		self.public_keys=public_keys
		self.keys_msg=keys_msg
		self.incr_msg=incr_msg
		self.temp=temp

	def run(self):
		
		while True:
			#On récupère les messages:
			#print("Attente de réception d'un message")
			message=self.socket.next_message_decode()
			#print("Réception d'un message")
			type_msg=message["type_msg"]
			
			if type_msg=="demande_auth_1": #1ère PARTIE DE L'AUTHENTIFICATION
				#On récupère les informations envoyées par l'emetteur:
				emetteur=message["emetteur"]
				#On informe l'utilisateur de la demande de connexion:
				print("Demande d'authentification de "+emetteur)
				#On stocke les informations reçues dans le fichier temporaire
				self.temp[emetteur]={}
				n2_recu=message["content"]["n2"]
				self.temp[emetteur]["n2"]=hexToByte(n2_recu)
			 
			if type_msg=="demande_auth_2": #2ème PARTIE DE L'AUTHENTIFICATION
				emetteur=message["emetteur"]
				n_A=self.temp[emetteur]["n_perso"]
				n2_B_recu=message["content"]["n2_2"]
				n2_B=hexToByte(n2_B_recu)
				l_B=message["content"]["l"]
				#A retrouve n_B = D(k_A, n’_B) 
				#et vérifie que h(n_A :n_B) = l_B.
				#Il calcule aussi l_A = h(n_B :n_A)

				#on commence par déchiffrer ce qu'on a eu de B
				cipher = PKCS1_OAEP.new(self.private_key)
				message2 = cipher.decrypt(n2_B)
				Dn_B = int.from_bytes(message2, byteorder='big')

				#on vérifie que h(n_A :n_B) = l_B.
				#calcul du hash de (n_A;n_B) mais ici Dn_B et on le nomme Hl_B
				from Crypto.Hash import SHA256
				#on va caster (n_A:Dn_B) en entiers
				h = SHA256.new()
				h.update("{0}:{1}".format(n_A, Dn_B).encode('ASCII'))
				Hl_B = h.hexdigest()

				if (l_B == Hl_B):
					print("Authentification réussie !! :)")
					#On détermine les clefs pour les échanges:
				else :
					print("Erreur dans l'authentification")

				#on calcule aussi l_A = h(n_B:Dn_A)
				#on va caster (Dn_B:n_A) en entiers
				h = SHA256.new()
				h.update("{0}:{1}".format(Dn_B, n_A).encode('ASCII'))
				l_A = h.hexdigest()
				
				#On envoie l_A à emetteur:
				self.socket.envoyer_message('demande_auth_3', self.id_user, [emetteur], l_A)
				
				#ON CRÉE LES CLÉS POUR L'ÉCHANGE DE MESSAGES
				#enfin, on crée la clé k_AB pour que A parle à B
				h = SHA256.new()
				h.update("{0}:{1}:{2}".format(Dn_B, n_A, "AB").encode('ASCII'))
				ksd = h.digest()[:16]
				
				h = SHA256.new()
				h.update("{0}:{1}:{2}".format(n_A, Dn_B, "BA").encode('ASCII'))
				kds = h.digest()[:16]

				#On stocke les clés pour l'échange avec emetteur:
				self.keys_msg[emetteur]={}
				self.keys_msg[emetteur]['ksd']=ksd
				self.keys_msg[emetteur]['kds']=kds
				
			if type_msg=="demande_auth_3": #3ème PARTIE DE L'AUTHENTIFICATION
				emetteur=message["emetteur"]
				l_autre=message["content"]

				#On peut vérifier l'authentification:
				h = Crypto.Hash.SHA256.new()
				Dn_A=self.temp[emetteur]["n_demandeur"]
				n_B=self.temp[emetteur]["n_perso"]
				h.update("{0}:{1}".format(n_B,Dn_A).encode('ASCII'))
				Hl_A = h.hexdigest()

				if (l_autre == Hl_A):

					print("Authentification réussie !! :)")
					#On détermine les clefs pour les échanges:

					h = Crypto.Hash.SHA256.new()
					h.update("{0}:{1}:{2}".format(n_B, Dn_A, "AB").encode('ASCII'))
					kds = h.digest()[:16]
				
					h = Crypto.Hash.SHA256.new()
					h.update("{0}:{1}:{2}".format(Dn_A, n_B, "BA").encode('ASCII'))
					ksd = h.digest()[:16]

					#On stocke les clés pour l'échange avec emetteur:
					self.keys_msg[emetteur]={}
					self.keys_msg[emetteur]['ksd']=ksd
					self.keys_msg[emetteur]['kds']=kds

				else :
					print("Erreur dans l'authentification")
				

			elif type_msg=="message":
				
				emetteur=message["emetteur"]
				content=message["content"] #on récupère le contenu du message au format json
				message_c=hexToByte(content["message"])
				
				#On décode le message et on l'affiche
				message_dechiffre, resume_B = c.retrouver_message(message_c, hexToByte(content[self.id_user]['k']), self.keys_msg[emetteur]['kds'], int(content["incr"]))
				
				#print(message_dechiffre)
				#print(resume_B)
				#On vérifie l'intégrité du message:
				if(resume_B !=hexToByte(content[self.id_user]["r"])):
					print("Problème d'intégrité du message")
				else:
					print(emetteur+" : "+message_dechiffre)
				
			elif type_msg=="msg_serveur": #Réponse du serveur lors de la 1ère connexion
				print("Reception d'un message du serveur")
				#On récupère les clés publiques des utilisateurs connectés:
				cles_publiques=message["content"]
				msg=""
				for user in cles_publiques.keys():
					#On ajoute l'utilisateur dans la liste du client:
					K=(cles_publiques[user]['n'],cles_publiques[user]['e'])
					oK=RSA.construct(K)
					self.public_keys[user]=oK
					msg=msg+user+", "
				print("Liste des utilisateurs connectés: "+msg)

			elif type_msg=="nv_client":
				content=message["content"]
				id_nv_client=content["id"]
				public_key=content["clé"]
				if id_nv_client in self.public_keys:
					dk={'n':self.public_keys[id_nv_client].n, 'e':self.public_keys[id_nv_client].e}
					if public_key!=dk:
						print("Attention !!  Changement de clé publique de "+id_nv_client)

				K=(public_key['n'],public_key['e'])
				oK=RSA.construct(K)
				
				self.public_keys[id_nv_client]=oK #On crée une nouvelle clé publique dans la liste des clés publiques
				save_public_keys(self.public_keys, 'public_keys.json')
				
				print("Un nouvel utilisateur s'est connecté: "+id_nv_client)
					

class User:
	def __init__(self, id_user, host, port):
		self.id_user=id_user
		self.socket=reseau.MySocket()
		self.keys_msg={}
		self.incr_msg=0
		self.temp={}
		#créer une paire de clés pour A :
		print('création d\'une paire de clés publique/privée')
		
		if not os.path.exists(self.id_user + '.pem'): 
			mdp1 = input('création d\'une clé publique pour '+self.id_user + '\nEntrer un mot-de-passe\n')
			A = RSA.generate(2048)
			K_A = (A.n, A.e)
			k_A = (A.n, A.e, A.d)
			#on fait des objets de clés
			oK = RSA.construct(K_A)
			ok = RSA.construct(k_A)
			#créer une paire de clés pour B :
			#on les enregistre dans un dossier
			f = open(self.id_user + '.pem','bw')
			f.write(A.exportKey('PEM', passphrase=mdp1))
			f.close()
		else :
			print('le nom '+ self.id_user + ' est déjà utilisé')


		if os.path.exists(self.id_user + '.pem'): 
			# On le récupère
			try :
				mdp2 = input('recherche du nom ' + self.id_user + ' dans le dossier\nEntrer votre mot-de-passe\n')
				f = open(self.id_user + '.pem','br')
				A = RSA.importKey(f.read(), passphrase=mdp2)
				K_A = (A.n, A.e)
				k_A = (A.n, A.e, A.d)
				oK = RSA.construct(K_A)
				ok = RSA.construct(k_A)
				f.close()
				
			except ValueError:
				print('Mauvais mot-de-passe pour ' + self.id_user)

		else: # Le fichier n'existe pas
			print(nom + ' n\'existe pas, merci de créer des clefs')
			i = 1

		self.private_key=ok
		jK={'n':A.n,'e':A.e}
		self.public_keys={}
		if os.path.exists('public_keys.json'): 
			f=open('public_keys.json','r')
			keys=json.loads(f.read())
			for user in keys.keys():
				K=(keys[user]['n'],keys[user]['e'])
				oK=RSA.construct(K)
				self.public_keys[user]=oK

		self.public_keys[id_user]=oK
		self.socket.connect((host, port))#envoi d'une demande de connexion au serveur
		self.envoi=Sender(self.socket,self.id_user,self.private_key,self.public_keys,self.keys_msg,self.incr_msg,self.temp)
		self.reception=Receiver(self.socket,self.id_user,self.private_key,self.public_keys,self.keys_msg,self.incr_msg,self.temp)
		self.envoi.start()
		self.reception.start()
		time.sleep(1)
		#On envoie des infos au serveur:
		self.socket.envoyer_message("identification",self.id_user,[],jK)	
	

id_user=sys.argv[1]
host=sys.argv[2]
port=int(sys.argv[3])

user=User(id_user, host, port)

