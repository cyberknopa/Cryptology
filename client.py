import socket
from utils.aes import AES
from utils.rsa import encrypt, decrypt, generateKey
#данные для ДХ
b = 11 #секретный ключ
d = 977
n = 29

#AES, инициализирующий вектор
iv = b'1234567887654321'

#данные для RSA
p = 1093	
q = 1097
publicKey, privateKey = generateKey(p, q)

#подключение к серверу
connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
IP = "127.0.0.1"
PORT = 12333
connection.connect((IP, PORT))

#Диффи Хеллман 
rd = connection.recv(1024)
print(rd.decode('utf8'))
connection.send("Key exchange from client".encode('utf8'))
rd = connection.recv(1024)
print('part from serv:', rd.decode('utf8'))
tmp = str(rd.decode('utf8'))
f1 =  int(tmp)
key = (f1 ** b) % d
tmp = str((n ** b) % d)
connection.send(tmp.encode('utf8'))
print("AES KEY is:", key)

#ключ для АЕС
aes_key = str(key)
k = 16 - len(aes_key)
aes_key = '0'*k + aes_key



#получение и расшифровка ключа сервера
rd = connection.recv(1024)
encrypted_key = str(AES(aes_key.encode()).decrypt_ctr(rd, iv).decode('utf8'))
tmparr = encrypted_key.split('-')
key_msg = "Server public key: (" + tmparr[0] + ", " + tmparr[1] + ")"
print(key_msg)
serv_publicKey = (int(tmparr[0]), int(tmparr[1]))

#отправка своего ключа
rsa_key = str(publicKey[0]) + "-" + str(publicKey[1])
encrypted = AES(aes_key.encode()).encrypt_ctr(rsa_key.encode(), iv)
connection.send(encrypted)

#Ожидание ответа о готовности общаться
rd = connection.recv(1024)
print(str(rd.decode('utf8')))

#чат с сервером
while True:
    msg = str(input("Write message to server: "))
    if (msg == "!stop"):
        connection.close()
        break
    encrypted = encrypt(serv_publicKey, msg)
    connection.send(encrypted.encode('utf-8'))

    rd = connection.recv(1024)
    encrypted = str(rd.decode('utf8'))
    msg = decrypt(privateKey, encrypted)
    print("Message from server:", msg)



