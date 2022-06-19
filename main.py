import sys
import Cryptodome
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import rsa
import trng
import hashlib
import PySimpleGUI as sg
import binascii

#input message and generate SHA
layout = [[sg.Text('Wprowadź wiadomość, którą chcesz zaszyfrować: ')],
                 [sg.InputText()],
                 [sg.Submit(), sg.Cancel()]]


window = sg.Window('Window Title', layout)
event, values = window.read()
window.close()
message = values[0]
sg.popup('Wprowadzona wiadomość: ', message)

messageSHA = hashlib.sha3_224(message.encode('ascii')).hexdigest().encode('ascii')

#generate a pair of keys
randNum = trng.obtain()
length = 0
if randNum < 85: length = 1024
elif (randNum >= 85) and (randNum < 170): length = 2048
else: length = 3072
keyPair = RSA.generate(length)
pubKey = keyPair.publickey()
sg.popup('Klucz publiczny: ', pubKey.n)

#encryption
encryptor = PKCS1_OAEP.new(pubKey)
encrypted = encryptor.encrypt(messageSHA)
sg.popup('Zakodowana wiadomość: \n' + str(encrypted))

layout = [[sg.Text('Jeśli chcesz zmodyfikować klucz prywatny, to zrób to teraz lub zostaw go bez zmian: ')],
                 [sg.InputText(default_text=keyPair.export_key().decode('ascii'))],
                 [sg.Submit(), sg.Cancel()]]

window = sg.Window('Window Title', layout)
event, values = window.read()
window.close()
if values[0] == keyPair.export_key().decode('ascii'):
  sg.popup('Klucz prywatny jest poprawny,\nnastąpi teraz odszyfrowanie wiadomości.')
else:
  sg.popup('Klucz prywatny jest nieprawidłowy.\nProgram zakończy teraz swoje działanie')
  sys.exit()

#decryption
decryptor =  PKCS1_OAEP.new(keyPair)
decrypted = decryptor.decrypt(encrypted)
receivedMessage = message

layout = [[sg.Text('Teraz możesz zmodyfikować otrzymaną wiadomość.\nJeśli nie chcesz tego robić, przejdź dalej. ')],
                 [sg.InputText(default_text = receivedMessage)],
                 [sg.Submit(), sg.Cancel()]]


window = sg.Window('Window Title', layout)
event, values = window.read()
window.close()

#SHA check
receivedMessageSHA = hashlib.sha3_224(values[0].encode('ascii')).hexdigest().encode('ascii')
if(receivedMessageSHA == decrypted):
  sg.popup("SHA są zgodne")
else:
  sg.popup("SHA nie są zgodne. Ktoś mógł ingerować w plik.")
