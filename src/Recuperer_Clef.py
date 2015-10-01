#!/usr/bin/env python3
# -*- coding: utf8 -*-


import Cryptographie as c
import Crypto
import Crypto.Random.random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import os


nom = input("Entrez votre identifiant : ")  
while True:
    CHOIX = input("Pour créer une paire de clés publique/privée taper 1\n Si ils existent déjà taper 2\n Pour envoyer des messages taper 3\n")
    i = int (CHOIX)    
    if i == 1 :
        if not os.path.exists(nom + '.pem'): 
            mdp1 = input('création d\'une clé publique pour '+nom + '\nEntrer un mot-de-passe\n')
            A = RSA.generate(2048)
            K_A = (A.n, A.e)
            k_A = (A.n, A.e, A.d)
            #on fait des objets de clés
            oK_A = RSA.construct(K_A)
            ok_A = RSA.construct(k_A)
            #créer une paire de clés pour B :
            #on les enregistre dans un dossier
            f = open(nom + '.pem','bw')
            f.write(A.exportKey('PEM', passphrase=mdp1))
            f.close()
        else :
            print('le nom '+ nom + ' est déjà utilisé')

    if i == 2 :   
        if os.path.exists(nom + '.pem'): 
            # On le récupère
            try :
                mdp2 = input('recherche du nom ' + nom + ' dans le dossier\nEntrer votre mot-de-passe\n')
                f = open(nom + '.pem','br')
                key = RSA.importKey(f.read(), passphrase=mdp2)
                f.close()
                print(key)
            except ValueError:
                print('Mauvais mot-de-passe pour ' + nom)

        else: # Le fichier n'existe pas
            print(nom + ' n\'existe pas, merci de créer des clefs')
            i = 1

    if i == 3 :
        while True :
            msg = input('Message qu\'envoie A à B, C, D...')
            i_A += 1
            print(i_A)
            
            print('chez A')
            msg_chiffre, cles, resumes = c.pret_a_envoyer(msg, destA, i_A)
            
            print(msg_chiffre)
        
            print('chez B ')
            message_dechiffre, resume_B = c.retrouver_message(msg_chiffre, cles['B'], destB['A']['kd'], i_A)
            print(message_dechiffre)    
                
            
            print(str(resumes['B']) + " " + str(resume_B))    
                
            if (msg == message_dechiffre):
                if (resumes['B'] == resume_B):
                    print('Transmission réussie')
                else :
                    print('Erreur de hashage')
            else :
                print('erreur')        
            


...
f = open('mykey.pem','r')
key = RSA.importKey(f.read())
f.close()
