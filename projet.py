# Module permettant de 'normaliser' un texte comprenant des caractères accentués.
import unidecode

# Module de génération pseudo-aléatoire. Permet de générer une permutation pseudo-aléatoire 
# des lettres de l'alphabet dans la fonction genererCle() pour générer une clé d'encryption/décryption 
# pour l'encryption par substitution.
import random 

# Module de génération aléatoire. Permet de générer aléatoirement un nombre de n bits dans l'encryption par la méthode RSA.
# Permet également de choisir un entier a de façon aléatoire pour le générateur de nombres premiers
import secrets

#Permet d'effectuer la décomposition en facteurs premiers dans le générateur de nombres premiers
from functools import reduce

alphabet = 'abcdefghijklmnopqrstuvwxyz'

#https://www.apprendre-en-ligne.net/crypto/stat/francais.html => proportions de la langue française
frequence = dict(zip(alphabet, (2, 18, 12, 11, 1, 17, 16, 20, 4, 22, 25, 8, 14, 5, 10, 13, 19, 7, 3, 6, 9, 15, 26, 21, 23, 24))) 

#------------César------------

# Permet d'encrypter un texte avec le décalage précisé par la clé.
# Pour l'utiliser en décryption => paramClé: -(cléDeDécalage)
def encrypteCesar(texte: 'Texte à encrypter ou à décrypter', cle: 'Clé de décalage pour l\'encryption ou la décryption') -> 'Texte encrypté ou décrypté':
    texte = unidecode.unidecode(texte).lower()
    texteCrypte = ""
    for lettre in texte: 
        if lettre in alphabet:
            # On ajoute à la position de la lettre au sein de l'alphabet le décalage et on fait mod 26
            texteCrypte += alphabet[(alphabet.index(lettre) + cle) % 26]
        else:
            texteCrypte += lettre
    return texteCrypte

# Permet de retrouver la clé de décalage d'un texte encrypté
# On assume que la lettre la plus récurrente du texte encrypté est associé à la lettre 'e' et qu'il y a qu'une seule lettre associée à celle-ci. 
def trouverCleCesar(texte: 'Texte encrypté à analyser') -> 'Clé de décalage utilisée pour encrypter le texte':
    texte = unidecode.unidecode(texte).lower()

    #On compte le nombres de lettres dans le message crypté
    frequenceDesLettres = dict(zip(alphabet, [0]*26))
    for lettre in frequenceDesLettres:
        frequenceDesLettres[lettre] += texte.count(lettre)

    # On trouve la lettre la plus récurrente dans le message
    valeurMaximale = max(frequenceDesLettres.items(), key = lambda n: n[1])

    # Si la position de cette lettre est au-dessus ou égale de celle de la lettre e dans l'alphabet
    if alphabet.index(valeurMaximale[0]) >= alphabet.index('e'):
        return (alphabet.index(valeurMaximale[0]) - alphabet.index('e'))

    #Si elle est en-dessous
    else:
        return -(alphabet.index('e') - alphabet.index(valeurMaximale[0]))

#------------Substitution------------

# Permet de générer une clé aléatoire en effectuant une permutation des lettres de l'alphabet
def genererCle() -> 'Clé d\'encryption/décryption':
    return ''.join(random.sample(alphabet, len(alphabet)))

# Permet d'encrypter ou de décrypter un texte avec la substitution précisée par la clé.
# Intervertir l'ordre entre l'alphabet et la clé afin de décrypter.
def encrypteSubstitution(texte: 'Texte à encrypter ou à décrypter', alphabet: 'Alphabet à utiliser pour l\'encryption', cle: 'Clé à utiliser pour l\'encryption') -> 'Texte encrypté ou décrypté':
    texte = unidecode.unidecode(texte).lower()
    texteCrypte = ""
    for lettre in texte:
        if lettre in alphabet:
            texteCrypte += cle[alphabet.index(lettre)]
        else:
            texteCrypte += lettre
    return texteCrypte

# Permet de retrouver la clé d'encryption
# On assume que les proportions de la langue française citées plus haut sont respectées à la lettre
def trouverCleSub(texteCrypte: 'Texte encrypté à analyser') -> 'Clé utilisé pour l\'encryption':
    texteCrypte = unidecode.unidecode(texteCrypte)

    # On crée un dictionnaire avec les lettres de l'alphabet et on associe la valeur 0 à chacune
    frequenceDesLettres = dict(zip(alphabet, [0] * 26))

    # On compte les lettres du texte crypté
    for lettre in frequenceDesLettres:
        frequenceDesLettres[lettre] += texteCrypte.count(lettre)

    # Classe les lettres en ordre de position de fréquence dans la langue francaise ({'e': 1, ...}), on prend seulement les clés
    frequenceEnOrdre = {cle: valeur for cle,valeur in sorted(frequence.items(), key = lambda n: n[1])}.keys()

    # Classe les lettres selon leur fréquence dans le texte en ordre décroissant, on prend seulement les clés
    frequenceDesLettresEnOrdre = {cle: valeur for cle,valeur in sorted(frequenceDesLettres.items(), key = lambda n: n[1], reverse = True)}.keys()

    # On associe les clés des deux dictionnaires ensemble
    associationDesLettres = dict(zip(frequenceEnOrdre, frequenceDesLettresEnOrdre))

    # On réarrange les clés de ce dictionnaire en ordre alphabétique de clé, puis on garde seulement les valeurs associés à chaque clé. En fusionnant tous les caractères retournés par l'objet dict_items, on obtient la clé de décryptage
    cle = dict(sorted(associationDesLettres.items())).values()
    return ''.join(cle)

#----------------------------Vigenere-----------------------------

# Permet d'encrypter ou de décrypter un texte en utilisant le chiffrement de Vigenère
def encrypteVigenere(texte: 'Texte à encrypter ou à décrypter', cle: 'Clé d\'encryption/décryption', encrypte: 'Mode: Encryption => True, Décryption => False (True par défaut)' = True) -> 'Texte encrypté ou décrypté':
    texte = unidecode.unidecode(texte).lower()
    cle = unidecode.unidecode(cle).lower()
    texteCrypte = ""
    i = 0

    #Si on veut crypter
    if encrypte == True:
        for lettre in texte:
            if lettre in alphabet:
                # On ajoute à la position de la lettre du texte décrypté la position de la ième lettre de la clé au sein de l'alphabet et on fait mod 26 
                texteCrypte += alphabet[(alphabet.index(lettre) + alphabet.index(cle[i % len(cle)])) % 26]
                i += 1
            else:
                texteCrypte += lettre

    #Si on veut décrypter
    else:
        for lettre in texte:
            if lettre in alphabet: 
                # On soustrait à la position de la lettre du texte crypté la position de la ième lettre de la clé au sein de l'alphabet et on fait mod 26 
                texteCrypte += alphabet[(alphabet.index(lettre) - alphabet.index(cle[i % len(cle)])) % 26]
                i += 1
            else:
                texteCrypte += lettre

    return texteCrypte

# Effectue l'examination de kasiski sur un texte crypté donné.
def kasiski(texte: 'Texte encrypté à analyser') -> 'Texte décrypté':
    table = []
    espacements = []
    cesars_encryptes = []
    texte = ''.join(tuple(filter(str.isalpha, unidecode.unidecode(texte.lower()))))
    texteDecrypte = ''

    #Toutes les combinaisons possibles de 3 lettres (grp = 3 lettres)
    for i in range(len(texte) - 2):
        grp = texte[i:(i+3)]
        table.append(grp)

    #On filtre les groupements pour garder seulement ceux qui se repetent plus d'une fois
    tableValeurs = dict(zip(table, [0] * len(table)))
    for elem in table:
        tableValeurs[elem] += 1
    
    tableValeurs = dict(filter(lambda n: n[1] > 1, tableValeurs.items()))

    #Calculer les espacements entre les groupements de 3 lettres
    for cle, valeur in tableValeurs.items():
        indexes = [index for index, elem in enumerate(table) if elem == cle]
        espacements.append(indexes[1] - indexes[0])

    # Choix du PGCD (PGCD => Longueur de la clé)
    print(tableValeurs)
    print(espacements)
    print('PGCD?')
    pgcd = int(input())

    #Séparation du texte selon la longueur de la clé
    for i in range(pgcd):
        cesars_encryptes.append(texte[i:len(texte):pgcd])

    # Décryption de chacun des textes avec la méthode de décryption sans la clé de césar
    cesars_decryptes = list(map(lambda n: encrypteCesar(n, -(trouverCleCesar(n))), cesars_encryptes))
    print(cesars_decryptes)

    #Ajout d'espaces pour avoir des textes de même longueur (Si les textes sont de longueurs différentes)
    texteLePlusLong = len(max(cesars_decryptes, key = lambda k: len(k)))
    cesars_decryptes = [elem if len(elem) == texteLePlusLong else (elem + (' ' * (texteLePlusLong - len(elem)))) for elem in cesars_decryptes]

    # Reformation du texte d'origine décrypté
    for i in range(texteLePlusLong):
        for elem in cesars_decryptes:
            texteDecrypte += elem[i]

    return ''.join(tuple(filter(str.isalpha, unidecode.unidecode(texteDecrypte.lower()))))



#----------RSA----------

#Permet de générer des nombres premiers de façon déterministe
def generateurPremier(b: 'taille en bytes') -> 'Nombre premier':
    # On génère un nombre aléatoire en dessous de n
    a = int(secrets.randbits(b))

    # Si le nombre ne se termine pas par 1,3,7 ou 9, on en génère un nouveau
    if a % 10 not in {1,3,7,9}:
        return generateurPremier(b)

    #On décompose en facteurs premiers
    #https://stackoverflow.com/questions/6800193/what-is-the-most-efficient-way-of-finding-all-the-factors-of-a-number-in-python
    factors = set(reduce(list.__add__, ([i, a//i] for i in range(1, int(a**0.5) + 1) if a % i == 0)))

    #Si seulement deux facteurs (1 et le nombre lui-même), c'est un nombre premier et on le retourne
    if len(factors) == 2:
        return a
    return generateurPremier(b)

	
# Détermine le plus grand diviseur commun de deux nombres en utilisant l'algorithme d'Euclide
def pgcd(a: 'Premier nombre premier', b: 'Deuxième nombre premier') -> 'Plus grand diviseur commun':
	r = a % b

	while r > 0:
		a = b
		b = r
		r = a % b
	return b

# Retourne un nombre e aléatoire t. q. pgcd(e, ϕ(n)) == 1
def cleEncryption(p: 'Premier nombre premier', q: 'Deuxième nombre premier', b: 'Taille en bytes') -> 'Clé d\'encryption':
	e = int(secrets.randbits(b))

    # Si e n'est pas dans l'ensemble {1, 2, ... n - 1}
	if e > (p * q - 1) or e < 1: 
		return cleEncryption(p, q, b)

    # Si le pgcd de e et ϕ(n) est différent de 1
	if pgcd(e, (p - 1) * (q - 1)) != 1:
		return cleEncryption(p, q, b)

	return e

# Calcule d t. q. ed ≡ 1 (mod ϕ(n))
def cleDecryption(p: 'Premier nombre premier', q: 'Deuxième nombre premier', e: 'Clé d\'encryption') -> 'Clé de décryption':
    # Pow() est une fonction qui permet de calculer l'inverse modulaire modulo n de e
    # https://docs.python.org/3/library/functions.html#pow
	return pow(e, -1, (p - 1) * (q - 1)) % ((p - 1) * (q - 1))
	
#Permet d'encrypter un message à l'aide de la méthode RSA
def encrypteRSA(p: 'Premier nombre premier', q: 'Deuxièmre nombre premier', m: 'Message', b: 'Tailles en bytes (8 par défaut)' = 8) -> 'Message encrypté':
	n = p * q

    # On choisit e
	e = cleEncryption(p, q, b)
    # On calcule d
	d = cleDecryption(p, q, e)

    # Si d est égal à e, on choisit un autre nombre e
	if d == e:
		return encrypteRSA(p, q, m, b)

    # Si le pgcd du message et du nombre n est différent de 1, on retourne une erreur et il faut, idéalement, ajuster le message
	if pgcd(m, n) != 1:
		raise ValueError('Le message et l\'entier n ne sont pas relativement premiers')
	print(f'Clé d\'encryption: {e}\n\n', f'Clé de décryption: {d}\n\n' f'Message encrypté: {pow(m, e, n)}\n')

    # Pow() permet également de faire de l'exponentiation modulo n. Voir documentation python ctiée dans la fonction cleDecryption
	return pow(m, e, n)

# Permet de décrypter un message à l'aide de la méthode RSA
def decrypteRSA(a: 'Message encrypté', d: 'Clé de décryption', p: 'Premier nombre premier', q: 'Deuxième nombre premier') -> 'Message décrypté':
	n = p * q
	print(f'Message encrypté: {a}\n\n' f'Clé de décryption: {d}\n\n' f'Message décrypté: {pow(a, d, n)}\n')
	return pow(a, d, n)
    

        



