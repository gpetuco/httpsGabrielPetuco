import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Cipher import AES
import os

# Aluno: Gabriel Frigo Petuco

#Valores de p e g fornecidos pelo professor Edson
p_hex = (
    "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
    "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
    "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
    "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
    "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
    "DF1FB2BC2E4A4371"
)
g_hex = (
    "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
    "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
    "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
    "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
    "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
    "855E6EEB22B3B2E5"
)

# Chave privada de 30 dígitos
a = 123456789012345678901234567890

# Converte p e g
p = int(p_hex, 16)
g = int(g_hex, 16)

#Diffie Hellman
# A = g^a mod p
A = pow(g, a, p)

# Abaixo, o valor de A informado ao professor no Moodle, convertido em hexadecimal
print(f"Valor de A: {hex(A)[2:].upper()}")

# B do professor Edson, fornecido no Moodle
B_hex = "008DC95194C5F1A0490A284686DEF42F8A03F33D590ECAFF9A273507118C0C88FC67748B1AE33001CC9C5D13E5C12C5EA7920FC1F50D1E3F9E43ACC61950FE69004BD7AE763FB5F7D6DD8F6684C9335F5B158416722FE31389BAD9FCF086C7156F047FA087BB635E024BB0344503CC12108881846A26AA2677F95C052D8CFB5D9D"
# Converte
B = int(B_hex, 16)

# V = B^a mod p
def calculaV(B, a, p):
    return pow(B, a, p)

V = calculaV(B, a, p)
print("V = ", V)

# Derivar chave AES de 128 bits
V_bytes = V.to_bytes((V.bit_length() + 7) // 8, byteorder="big")
S_full = hashlib.sha256(V_bytes).digest()
S_key = S_full[-16:]  # 128 bits menos significativos

print(f"Chave: {S_key.hex().upper()}")

# Descriptografa os dados usando AES (CBC).
# Entrada: string hexadecimal [128 bits de IV][mensagem].
def descriptografaMensagem(chaveSecao, mensagemCriptografada):
    enc = bytes.fromhex(mensagemCriptografada)
    iv = enc[:AES.block_size]
    cipher = AES.new(chaveSecao, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(enc[AES.block_size:]), AES.block_size)
    return plaintext.decode('utf-8')
    
# Inverte a mensagem fornecida
def inverteMensagem(mensagem):
    return mensagem[::-1]

def criptografaMensagem(chaveSecao, mensagem):
    # IV (16 bytes)
    iv = os.urandom(AES.block_size)
    
    # Converte a mensagem para bytes
    mensagem_bytes = mensagem.encode('utf-8')
    
    # Aplica o padding para garantir que a mensagem tenha múltiplos de 16 bytes
    mensagem_padded = pad(mensagem_bytes, AES.block_size)
    
    # Objeto de criptografia AES com modo CBC
    cipher = AES.new(chaveSecao, AES.MODE_CBC, iv)
    
    # Criptografa a mensagem
    mensagem_criptografada = cipher.encrypt(mensagem_padded)
    
    # Retorna o IV e a mensagem criptografada como um único valor hexadecimal
    return (iv + mensagem_criptografada).hex()

# Mensagem cifrada fornecida em hexadecimal pelo professor Edson
mensagem_cifrada_hex = (
"e4964b319c6637f7a21cfc928494a9d3e8d947622c504703108b5eb7f1e9c80a1a284f9d61b67af086d035cb1ef433bdb877db37dfc629f1bcd0c93beb466880"
)

# Descriptografa
mensagemDecifrada = descriptografaMensagem(S_key, mensagem_cifrada_hex)
print(f"Mensagem decifrada: {mensagemDecifrada}")

# Inverte mensagem decifrada
mensagemInvertida = inverteMensagem(mensagemDecifrada)
print("Mensagem invertida: " , mensagemInvertida)

# Criptografa mensagem invertida
mensagemInvertidaCriptografada = criptografaMensagem(S_key, mensagemInvertida)

print("Mensagem invertida cifrada: " , mensagemInvertidaCriptografada)