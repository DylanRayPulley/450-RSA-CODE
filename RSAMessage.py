import rsa
import base64


def GenerateKeyPair():
    (public_key, private_key) = rsa.newkeys(256)
    p = open('publickey.pem', 'wb')
    p.write(public_key.save_pkcs1('PEM'))
    p.close
    p = open('privatekey.pem', 'wb')
    p.write(private_key.save_pkcs1('PEM'))
    p.close


def CollectPublicKey():
    p = open('publickey.pem', 'rb')
    public_key = rsa.PublicKey.load_pkcs1(p.read())
    p.close
    return public_key


def CollectReceivedPublicKey():
    p = open('receivedpublickey.pem', 'rb')
    public_key = rsa.PublicKey.load_pkcs1(p.read())
    p.close
    return public_key


def CollectPrivateKey():
    p = open('privateKey.pem', 'rb')
    private_key = rsa.PrivateKey.load_pkcs1(p.read())
    p.close
    return private_key






def EncryptMessage(text: str, key):
    encoded_text = text.encode()
    encrypted_message = rsa.encrypt(encoded_text, key)
    return base64.b64encode(encrypted_message).decode('ascii')


def DecryptMessage(text, key) -> str:
    #encrypted_text = text.encode()
    encrypted_bytes = base64.b64decode(text)
    decrypted_message = rsa.decrypt(encrypted_bytes, key)
    plain_text = decrypted_message.decode()
    return plain_text




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
            key = CollectReceivedPublicKey()
            message = EncryptMessage(user_input, key)
            print(f" Encrypted Text: {message}")
            p = open("EncryptedMessage.txt", 'w')
            print(message)
            p.write(message)
            p.close
        case '4':
            p = open("RecievedMessage.txt", 'r')
            user_input = p.read()
            p.close()
            key = CollectPrivateKey()
            message = DecryptMessage(user_input, key)
            print(f"Decrypted Message: {message}")
        case _:
            print("Incorrect Input Exiting Program")
            break
