#!/usr/bin/env python3

#on importe tout
import Crypto #pour n'appeller que c.quelquechose, plus simple
import Crypto.Random.random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP

print('etape 0°')
#créer une paire de clés pour A :
print('création d\'une clé publique pour A')
A = RSA.generate(2048)
K_A = (A.n, A.e)
k_A = (A.n, A.e, A.d)
#on fait des objets de clés
oK_A = RSA.construct(K_A)
ok_A = RSA.construct(k_A)
type(ok_A)

#créer une paire de clés pour B :
print('création d\'une clé publique pour B')
B = RSA.generate(2048)
K_B = (B.n, B.e)
k_B = (B.n, B.e, B.d)
#on fait des objets de clés
oK_B = RSA.construct(K_B)
ok_B = RSA.construct(k_B)
print("ok_A={0}".format(ok_A))
print("ok_B={0}".format(ok_B))

print('etape 1°, chez A')
#A connaît K_A, k_A et K_B. Il choisit n_A et calcule n2_A = E(K_B, n_A)
print('A va générer un n_A aléatoire')
n_A = Crypto.Random.random.getrandbits(128)
print("n_A={0}".format(n_A))
#on va caster n_A en une suite de bits
messageAB = n_A.to_bytes(16, byteorder='big')
#on va le chiffrer avec la clé publique de B
cipher = PKCS1_OAEP.new(oK_B)
n2_A = cipher.encrypt(messageAB)
print("n2_A={0}".format(n2_A))
print('n2_A créé')


#il faut donc envoyer {A, n2_A} chez B



print('etape 2°, chez B')
#B connaît K_B, k_B, K_A. Il déchiffre n_A = D(k_B, n2_A).
#puis B choisit n_B et calcule n2_B = E(K_A, n_B)
#ainsi que l_B = h(n_A :n_B)

#on commence par déchiffrer ce qu'on a eu de A et à le convertir en int Dn_A
cipher = PKCS1_OAEP.new(ok_B)
message = cipher.decrypt(n2_A)
Dn_A = int.from_bytes(message, byteorder='big')

#on génère n_B et on le chiffre
print('B va générer un n_B aléatoire')
n_B= Crypto.Random.random.getrandbits(128)
print("n_B={0}".format(n_B))
#on va caster n_B en une suite de bits
messageBA = n_B.to_bytes(16, byteorder='big')
#on va le chiffrer avec la clé publique de A cette fois
cipher = PKCS1_OAEP.new(oK_A)
n2_B = cipher.encrypt(messageBA)

#calcul du hash de (n_A;n_B) mais ici Dn_A
from Crypto.Hash import SHA256
#on va caster (Dn_A:n_B) en entiers
h = SHA256.new()
h.update("{0}:{1}".format(Dn_A, n_B).encode('ASCII'))
l_B = h.hexdigest()
print("l_B={0}".format(l_B))
#il faut donc envoyer {n2_B, l_B} chez A
print("n2_B={0}".format(n2_B))
print('n2_B créé')



print('etape 3°, chez A')
#A retrouve n_B = D(k_A, n’_B) 
#et vérifie que h(n_A :n_B) = l_B.
#Il calcule aussi l_A = h(n_B :n_A)

#on commence par déchiffrer ce qu'on a eu de B
cipher = PKCS1_OAEP.new(ok_A)
message2 = cipher.decrypt(n2_B)
Dn_B = int.from_bytes(message2, byteorder='big')

#on vérifie que h(n_A :n_B) = l_B.
#calcul du hash de (n_A;n_B) mais ici Dn_B et on le nomme Hl_B
from Crypto.Hash import SHA256
#on va caster (n_A:Dn_B) en entiers
h = SHA256.new()
h.update("{0}:{1}".format(n_A, Dn_B).encode('ASCII'))
Hl_B = h.hexdigest()
print("Hl_B={0}".format(Hl_B))

#on calcule aussi l_A = h(n_B:Dn_A)
#on va caster (Dn_B:n_A) en entiers
h = SHA256.new()
h.update("{0}:{1}".format(Dn_B, n_A).encode('ASCII'))
l_A = h.hexdigest()
print("l_A={0}".format(l_A))



print('etape 4°, chez B')
#B vérifie que h(n_B :n_A) == l_A
#calcul du hash de (n_B:Dn_A) mais ici B n'a que Dn_A et on le nomme Hl_A
#on va caster (n_B:Dn_A) en entiers
h = SHA256.new()
h.update("{0}:{1}".format(n_B, Dn_A).encode('ASCII'))
Hl_A = h.hexdigest()
print("Hl_A={0}".format(Hl_A))

if (l_B == Hl_B):
	if (l_A == Hl_A):
		print('Réussi')
	else :
		print('Erreur')
else :
	print('erreur')

#***************FIN de l'AUTHENTIFICATION***************************
