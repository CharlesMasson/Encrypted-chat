#!/usr/bin/env python3

#on importe tout
import Crypto
import Crypto.Random.random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES


#dests = {'B':{'K':K_B, 'ksd':k_AB, 'kds':k_BA}, 'C':... } sera la forme type du dictionnaire

#dests = {'B':{'K':0, 'ksd':0, 'kds':0, 'ns':0, 'nd':0 }, 'C':... } #forme initiale

#dests['B']['ksd']


#Il faut une clé de chiffrement spécifique au message :
def creer_cle(keys_msg, i):
	h = SHA256.new()
	#comment trouver tous les destinataires ?
	s = "{0}".format(i)
	for user in keys_msg.keys():
		s += ":{0}:{1}".format(keys_msg[user]['ksd'], keys_msg[user]['kds'])
	h.update(s.encode('ASCII'))
	kiv = h.digest()
	return kiv

def padding_message(msg):
	msg_encode = msg.encode('UTF-8')
	l_pad = 16 - (len(msg_encode)%16)
	#l_pad contient le nombre de caractères à rajouter et leur nombre de fois à rajouter (le même)
	msg_encode += l_pad.to_bytes(1, byteorder='big')*l_pad
	assert len(msg_encode)%16 == 0
	return msg_encode
    
def chiffrer_message(msg, kiv):
	k, iv = kiv[:16], kiv[16:32]
	cipher = AES.new(k, AES.MODE_CBC, iv)
	return cipher.encrypt(msg)     
    
def chiffrer_clef(kiv, keys_msg):  # pour tous les destinataires de dest
	clefs = {}
	for user in keys_msg.keys():
		ksd = keys_msg[user]['ksd']
		cipher = AES.new(ksd, AES.MODE_ECB)
		clefs[user] = cipher.encrypt(kiv)
	return clefs
    
def calculer_resumes(msg,keys_msg,i):
	h = SHA256.new()
	resumes = {}
	for user in keys_msg.keys():
		resumes[user] = calculer_hash(i, keys_msg[user]['ksd'], msg)
	return resumes 
    
# dests = { 'B':{'ksd':k_ab, 'kds':k_ba, 'ns':n_a, 'nd':n_b }, 'C':... } 

def pret_a_envoyer(msg, keys_msg, i):
	kiv = creer_cle(keys_msg, i)
	msg_encode = padding_message(msg)
	message_chiffre = chiffrer_message(msg_encode, kiv)    
	clefs = chiffrer_clef(kiv, keys_msg)
	resumes = calculer_resumes(msg, keys_msg, i)  
	return message_chiffre, clefs, resumes

# on passe au déchiffrage

def dechiffrer_cle(kivC, clef):        
	#kivB = clefs['B']
	#B retrouve k_AB dans destB
	#k_AB = destB['A']['kds']
	cipher = AES.new(clef, AES.MODE_ECB)
	Dkiv = cipher.decrypt(kivC)  
	return Dkiv
    
def dechiffrer_message(kiv, msg):       
	k, iv = kiv[:16], kiv[16:32]
	cipher = AES.new(k, AES.MODE_CBC, iv)
	Dmsg_padding = cipher.decrypt(msg)
	#rappel : on enleve le padding
	#assert Dmsg_padding[-1]>0 and Dmsg_padding[-1]<=16
	Dmsg_encode = Dmsg_padding[:-Dmsg_padding[-1]]
	Dmsg = Dmsg_encode.decode('UTF-8')
	return Dmsg

def calculer_hash(i, k, msg):
	#hash final on récupère les clés dans le dossier que possède B
	#on va caster (i_A:msg_encode:k_AB) en entiers
	h = SHA256.new()
	h.update("{0}:{1}:{2}".format(i,msg,k).encode('UTF-8'))
	r = h.digest()
	return r
 
def retrouver_message(msgch, clch, clef, i):
	kiv = dechiffrer_cle(clch, clef)
	msg_decode = dechiffrer_message(kiv, msgch)
	resume = calculer_hash(i, clef, msg_decode)
	return msg_decode, resume

    
    
    

