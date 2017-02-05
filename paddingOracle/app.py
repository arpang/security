#!/usr/bin/env python
import os
import json
from flask import Flask, render_template, request
from Crypto.Cipher import AES


app = Flask(__name__)

key = "AAAAAAAAAAAAAAAA"
blocksize = 16

def encrypt(message):
    IV = os.urandom(blocksize)
    aes = AES.new(key=key, IV=IV, mode=AES.MODE_CBC)
    padding_length = blocksize - len(message)%blocksize
    message += chr(padding_length) * padding_length
    ciphertext = aes.encrypt(message)
    return (IV + ciphertext).encode('hex')

def decrypt(ciphertext):
    ciphertext = ciphertext.decode('hex')
    if len(ciphertext) < blocksize: return ''
    IV = ciphertext[:blocksize]
    aes = AES.new(key=key, IV=IV, mode=AES.MODE_CBC)
    plaintext = aes.decrypt(ciphertext[blocksize:])
    if len(plaintext) == 0: return ''
    padding_length = ord(plaintext[-1])
    for i in plaintext[-padding_length:]:
        assert i == plaintext[-1]
    return plaintext[:-padding_length]

@app.route('/', methods=['GET', 'POST'])
def index():
    message = ""
    message_type = ""
    if request.method == 'POST':
        plaintext = decrypt(request.form['token'])
        try:
            data = json.loads(plaintext)
            message = "Welcome " + data['user']
            message_type = "alert-success"
        except:
            message = "Corrupted Token"
            message_type = "alert-danger"
    return render_template('index.html', message=message, message_type=message_type)

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)
