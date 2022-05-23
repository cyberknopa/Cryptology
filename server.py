from utils.aes import AES
import socket
from utils.rsa import encrypt, decrypt, generateKey

#данные для ДХ
a = 19 #секретный ключ
d = 977
n = 29

#AES, инициализирующий вектор
iv = b'1234567887654321'

#данные для RSA	
p = 1087
q = 1091
publicKey, privateKey = generateKey(p, q)

#запуск сервера
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
IP = socket.gethostbyname(socket.gethostname())
PORT = 12333
listener.bind((IP, PORT))
listener.listen(0)

connection, address = listener.accept()

#Диффи-Хеллман
connection.send("Key exchange from server".encode('utf8'))
data = connection.recv(1024).decode("utf8")
print(data)
tmp = (n**a) % d
connection.send(str(tmp).encode('utf8'))
rd = connection.recv(1024)
print('part from serv:', rd.decode('utf8'))
tmp = str(rd.decode('utf8'))
f1 =  int(tmp)
key = (f1 ** a) % d
print("AES KEY is:", key)

#подготовка ключа АЕС
aes_key = str(key)
k = 16 - len(aes_key)
aes_key = '0'*k + aes_key

#отправка своего ключа
rsa_key = str(publicKey[0]) + "-" + str(publicKey[1])
encrypted = AES(aes_key.encode()).encrypt_ctr(rsa_key.encode(), iv)
connection.send(encrypted)

#получение и расшифровка ключа клиента
rd = connection.recv(1024)
encrypted_key = str(AES(aes_key.encode()).decrypt_ctr(rd, iv).decode('utf8'))
tmparr = encrypted_key.split('-')
key_msg = "Server public key: (" + tmparr[0] + ", " + tmparr[1] + ")"
print(key_msg)
client_publicKey = (int(tmparr[0]), int(tmparr[1]))
connection.send(b'OK')

#Общение
while True:
    rd = connection.recv(1024)
    encrypted = str(rd.decode('utf8'))
    msg = decrypt(privateKey, encrypted)
    print("Message from clinet:", msg)
    
    msg = str(input("Write message to client: "))
    encrypted = encrypt(client_publicKey, msg)
    connection.send(encrypted.encode('utf-8'))
