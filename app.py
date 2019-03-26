from flask import Flask, render_template, request
from elgamal import *
import time
import os, json
from random import randint
from argparse import Namespace

app = Flask(__name__)
app.config['ROOT_PATH'] = app.root_path

output_path = '/static/output/'

@app.route("/")
def main():
    return render_template('index.html')

@app.route("/ecceg", methods=['GET'])
def eccegGET():
    return render_template('ecceg_option.html')

@app.route("/ecceg/genkey", methods=['POST'])
def eccegGenKey():
    # pubKey, privKey = genKeys()

    # filepath = app.root_path + output_path
    # with open(filepath + 'kunci.pub', 'w') as jf: json.dump(json.dumps(pubKey.__dict__), jf)
    # with open(filepath + 'kunci.pri', 'w') as jf: json.dump(json.dumps(privKey.__dict__), jf)
    
    return json.dumps({
        'error': False,
        # 'pubKey': output_path + 'kunci.pub?' + str(time.time()),
        # 'priKey': output_path + 'kunci.pri?' + str(time.time()),
    })

@app.route("/ecceg/decrypt", methods=['GET'])
def eccegDecryptGET():
    return render_template('ecceg_decrypt.html')

# @app.route("/ecceg/decrypt", methods=['POST'])
# def eccegDecryptPOST():
    
@app.route("/ecceg/encrypt", methods=['GET'])
def eccegEncryptGET():
    return render_template('ecceg_encrypt.html')

# @app.route("/ecceg/encrypt", methods=['POST'])
# def eccegEncryptPOST():

@app.route("/elgamal", methods=['GET'])
def elgamalGET():
    return render_template('elgamal_option.html')

@app.route("/elgamal/genkey", methods=['POST'])
def elgamalGenKey():
    pubKey, privKey = genKeys()

    filepath = app.root_path + output_path
    with open(filepath + 'kunci.pub', 'w') as jf: json.dump(json.dumps(pubKey.__dict__), jf)
    with open(filepath + 'kunci.pri', 'w') as jf: json.dump(json.dumps(privKey.__dict__), jf)
    
    return json.dumps({
        'error': False,
        'pubKey': output_path + 'kunci.pub?' + str(time.time()),
        'priKey': output_path + 'kunci.pri?' + str(time.time()),
    })

@app.route("/elgamal/decrypt", methods=['GET'])
def elgamalDecryptGET():
    return render_template('elgamal_decrypt.html')

@app.route("/elgamal/decrypt", methods=['POST'])
def elgamalDecryptPOST():
    
    # check file and public key
    if 'file' not in request.files or 'privKey' not in request.files:
        return json.dumps({
            'error': True,
            'data': 'File or Public Key not Found!',
        })

    # check file extension
    file = request.files['file']
    privKey = request.files['privKey']
    if os.path.splitext(privKey.filename)[1] != '.pri':
        return json.dumps({
            'error': True,
            'data': 'Public Key must be in .pri format',
        })

    # load File and Public Key
    filepath = app.root_path + output_path
    file.save(filepath + 'temp')
    privKey.save(filepath + 'kunci.pri')
    with open(filepath + 'kunci.pri', 'r') as f:
        privKey = json.load(f)
    privKey = json.loads(privKey, object_hook=lambda d: Namespace(**d))
    with open(filepath + 'temp', 'r') as f:
        msg = f.read()

    # decrypt
    dec, t = decrypt(privKey, msg)
    with open(filepath + 'decrypted', 'w') as f:
        f.write(dec)

    return json.dumps({
        'error': False,
        'plaintext': '0x' + (dec[:16]).encode('hex'),
        'ciphertext': '0x' + (msg[:16]).encode('hex'),
        'download': output_path + 'decrypted?' + str(time.time()),
        'time': t / 1000,
        'size': len(dec),
    })

@app.route("/elgamal/encrypt", methods=['GET'])
def elgamalEncryptGET():
    return render_template('elgamal_encrypt.html')

@app.route("/elgamal/encrypt", methods=['POST'])
def elgamalEncryptPOST():

    # check file and public key
    if 'file' not in request.files or 'pubKey' not in request.files:
        return json.dumps({
            'error': True,
            'data': 'File or Public Key not Found!',
        })

    # check file extension
    file = request.files['file']
    pubKey = request.files['pubKey']
    if os.path.splitext(pubKey.filename)[1] != '.pub':
        return json.dumps({
            'error': True,
            'data': 'Public Key must be in .pub format',
        })

    # load File and Public Key
    filepath = app.root_path + output_path
    file.save(filepath + 'temp')
    pubKey.save(filepath + 'kunci.pub')
    with open(filepath + 'kunci.pub', 'r') as f:
        pubKey = json.load(f)
    pubKey = json.loads(pubKey, object_hook=lambda d: Namespace(**d))
    with open(filepath + 'temp', 'r') as f:
        msg = f.read()

    # encrypt
    enc, t = encrypt(pubKey, msg)
    with open(filepath + 'encrypted.txt', 'w') as f:
        f.write(enc)

    return json.dumps({
        'error': False,
        'plaintext': '0x' + (msg[:16]).encode('hex'),
        'ciphertext': '0x' + (enc[:16]).encode('hex'),
        'download': output_path + 'encrypted.txt?' + str(time.time()),
        'time': t / 1000,
        'size': len(enc),
    })

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=1111, debug=True)
