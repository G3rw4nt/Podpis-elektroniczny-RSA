import sys
import Cryptodome
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import rsa
import trng
import hashlib
import PySimpleGUI as sg
import binascii

message = 'Wiadomosc'
messageSHA = hashlib.sha3_224(message.encode('ascii')).hexdigest().encode('ascii')
keyPair = RSA.generate(1024)
pubKey = keyPair.publickey()
encryptor = PKCS1_OAEP.new(pubKey)
encrypted = encryptor.encrypt(messageSHA)

decryptor =  PKCS1_OAEP.new(keyPair)
decrypted = decryptor.decrypt(encrypted)
if(messageSHA == decrypted):
  print("SHA correct")
else:
  print("SHA incorrect")
