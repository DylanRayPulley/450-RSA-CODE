import rsa
import base64

def GenerateKeyPair():
    (public_key, private_key) = rsa.newkeys(512)
    p = open('publicKey.pem', 'wb')
    p.write(public_key.save_pkcs1('PEM'))
    p.close
    p = open('privateKey.pem', 'wb')
    p.write(private_key.save_pkcs1('PEM'))
    p.close

def CollectPublicKey():
    p = open('publicKey.pem', 'rb')
    public_key = rsa.PublicKey.load_pkcs1(p.read())
    p.close
    return public_key

def CollectReceivedPublicKey():
    p = open('receivedpublicKey.pem', 'rb')
    public_key = rsa.PublicKey.load_pkcs1(p.read())
    p.close
    return public_key

def CollectPrivateKey():
    p = open('privateKey.pem', 'rb')
    private_key = rsa.PrivateKey.load_pkcs1(p.read())
    p.close
    return private_key

def EnterPublicKey():
    #return input_to_key
    pass

def EncryptMessage(text: str, key):
    encrypted_message = rsa.encrypt(text, key)
    return base64.b64encode(encrypted_message).decode('ascii')

def EncodeText(text:str):
    return text.encode()

def DecryptMessage(text, key) -> str:
    #encrypted_text = text.encode()
    encrypted_bytes = base64.b64decode(text)
    decrypted_message = rsa.decrypt(encrypted_bytes, key)
    plain_text = decrypted_message.decode()
    return plain_text


#rsa sign test
#rsa.sign(message, priv_key, hash_method): signs a message (bytes) using a private key (priv_key) and a specified hash_method
#rsa.verify(message, signiture, pub_key): Verifies a signiture (bytes) against a message (bytes) using a public key (pub_key)) returns name of the has used or signing
#Exercise use rsa
#(pub,priv) = rsa.newkeys(512) #python rsa module enfores a minimum key size of 512 bits for RSA signing operations
#msg = b'hello'
#signiture = rsa.sign(messaage, privatekey, 'SHA-256') #use private key to sing
#Verification = rsa.verify(message, signiture, publickey) #use public key to verify
#Raises VerificationError - when the signature doesnt match the message
# otherwise Returns the name of the used hash

def SignMessage(message, private):
    signature = rsa.sign(message, private, 'SHA-256')
    signature_64 = base64.b64encode(signature).decode('ascii')
    return signature_64

def VerifyMessage(message:str, b64signature, public):
    right_message = message.encode()
    signature = base64.b64decode(b64signature)
    verification = rsa.verify(right_message, signature, public)
    return verification

msg = '''
    Enter Number
    1: Generate Key Pair
    2: Enter A Key
    3: Enter Message to Encrypt
    4: Enter Message to Decrypt
'''

while True:
    input_val = input(msg)
    match input_val:
        case '1':
            public_key = GenerateKeyPair()
            print(f"Key Generated")

        case '2':
            public_key = CollectPublicKey()
            print(f"Public Key: {public_key}")

        case '3':
            user_input = input("Enter your message here: ")
            pub_key = CollectReceivedPublicKey()
            priv_key = CollectPrivateKey()
            encoded_message = EncodeText(user_input)
            local_signature = SignMessage(encoded_message, priv_key)
            message = EncryptMessage(encoded_message, pub_key)
            print(f" Encrypted Text: {message}\n Signiture: {local_signature}")
            p = open("EncryptedMessage.txt", 'w')
            p.write(message)
            p.close()
            p = open("Signiture.txt", "w")
            p.write(local_signature)
            p.close()

        case '4':
            p = open("RecievedMessage.txt", 'r')
            user_input = p.read()
            p.close()
            p = open("RecievedSignature.txt", 'r')
            recieved_signature = p.read()
            p.close()
            local_priv_key = CollectPrivateKey()
            local_pub_key = CollectPublicKey()
            message = DecryptMessage(user_input, local_priv_key)
            local_verification = VerifyMessage(message, recieved_signature, local_pub_key)
            print(f"Decrypted Message: {message}\n Verification: {local_verification}")

        case _:
            print("Incorrect Input Exiting Program")
            break
