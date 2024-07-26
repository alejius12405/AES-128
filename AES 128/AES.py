from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes



from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from PIL import Image
import numpy as np
import tkinter as tk
from tkinter import messagebox
from tkinter import scrolledtext
from base64 import b64encode
import binascii


sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
inv_s_box = (
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c7, 0x1c, 0xe1, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
)
class AESImageCipher:
    # Image
    url = None  # Ruta completa de la imagen
    image = None  # Objeto de la imagen
    image_name = None  # nombre de imagen sin extensiones
    path = None  # Ruta de la carpeta de la imagen
    image_size = None  # Resolucion de la iamgen
    image_ext = None

    # Cipher
    key = None
    iv = None
    mode = AES.MODE_ECB

    def __init__(self):
        pass

    def setImagePath(self, ruta: str):
        self.url = ruta
        aux = ruta.split("/")
        name = aux[-1].split(".")
        self.image_ext = name[-1]
        self.image_name = name[0]
        self.path = self.url.replace(aux[-1], "")
    
    def setKey(self, key: bytes):
       if len(key) == 16:
          self.key = key
       else:
         messagebox.showerror("Error", "La clave debe tener 16 caracteres sin espacios")

    def setIv(self, iv: bytes):
        if len(iv) == 16:
            self.iv = iv
        else:
            messagebox.showerror("Error", "El vector inicial debe tener 16 bytes")

    def setMode(self, modo: str):
        if(modo == 'ECB'):
            self.mode = AES.MODE_ECB
        elif(modo == 'CBC'):
            self.mode = AES.MODE_CBC
        elif(modo == 'CFB'):
            self.mode = AES.MODE_CFB
        elif(modo == 'OFB'):
            self.mode = AES.MODE_OFB
        else:
            print("Mode not recognized")
            messagebox.showinfo("Información", "Modo no reconocido pero se cifrara en modo ECB")

    def getMode(self):
        if(self.mode == AES.MODE_ECB):
            return "ECB"
        elif(self.mode == AES.MODE_CBC):
            return "CBC"
        elif(self.mode == AES.MODE_CFB):
            return "CFB"
        elif(self.mode == AES.MODE_OFB):
            return "OFB"
        else:
            return None
    
    def encrypt(self):
        if(self.url != None and self.key != None):
            print("Cifrando...")
            img = Image.open(self.url)
            self.image = np.array(img)
            # print(len(self.image))
            self.image_size = img.size
            #print(self.key, self.iv)
            new_url = self.path + self.image_name + "_e" + self.getMode() + "." + self.image_ext

            cipher = None
            if(self.getMode() != "ECB"):
                cipher = AES.new(self.key, self.mode, iv=self.iv)
            else:
                cipher = AES.new(self.key, self.mode) 

            ct_bytes = cipher.encrypt(
                pad(
                    self.image.tobytes(),
                    AES.block_size,
                )
            )
            img_data = np.frombuffer(ct_bytes)
            # print(len(img_data))

            image_nva = Image.frombuffer(
                "RGB",
                self.image_size,
                img_data
            )
            image_nva.save(
                new_url
            )
            print("Cifrado")
            messagebox.showinfo("Información", "Se a encriptado la imagen con AES 128")

    def decrypt(self):
        if self.url is not None and self.key is not None:
            print("Decifrando...")
            img = Image.open(self.url)
            self.image = np.array(img)
            self.image_size = img.size

            new_url = self.path + self.image_name + "_d" + self.getMode() + "." + self.image_ext
            cipher = None
            if self.getMode() != "ECB":
                cipher = AES.new(self.key, self.mode, iv=self.iv)
            else:
                cipher = AES.new(self.key, self.mode)

            encrypted_data = self.image.tobytes()  # Datos cifrados
            decrypted_data = cipher.decrypt(encrypted_data)
            # Aquí es donde aplicamos unpad al resultado del descifrado
            # Nota: Unpad solo es necesario si el último bloque de datos fue rellenado durante el cifrado,
            # lo cual debería aplicarse para el modo ECB y otros modos si se utilizó padding.
            try:
                decrypted_data = unpad(decrypted_data, AES.block_size, style='pkcs7')
            except ValueError:
                print("Error de padding en los datos descifrados. Asegúrate de que los datos estén correctos y completos.")
                
            img_data = np.frombuffer(decrypted_data, dtype=np.uint8)

            # Asegúrate de que la forma de img_data coincida con la estructura de la imagen original antes de cifrar
            img_data = img_data.reshape((img.size[1], img.size[0], -1))

            Image.fromarray(img_data).save(new_url)
            print("Decifrado")
            messagebox.showinfo("Información", "Se a decencriptado la imagen")


if __name__ == "__main__":

    key = b'Estos son 16 bts'
    iv = b'0123456789ABCDEF'
    cipher = AESImageCipher()
    cipher.setImagePath('images\Imagen1.bmp')
    cipher.setKey(key)
    cipher.setIv(iv)
    cipher.setMode("CBC")
    cipher.encrypt()

    cipher2 = AESImageCipher()
    cipher2.setImagePath('images\Imagen1_eCBC.bmp')
    cipher2.setKey(key)
    cipher2.setIv(iv)
    cipher2.setMode("CBC")
    cipher2.decrypt()

    key = b'Estos son 16 bts'
    iv = b'0123456789ABCDEF'
    cipher = AESImageCipher()
    cipher.setImagePath('images\Imagen2.bmp')
    cipher.setKey(key)
    cipher.setIv(iv)
    cipher.setMode("CBC")
    cipher.encrypt()

    cipher2 = AESImageCipher()
    cipher2.setImagePath('images\Imagen2_eCBC.bmp')
    cipher2.setKey(key)
    cipher2.setIv(iv)
    cipher2.setMode("CBC")
    cipher2.decrypt()

    key = b'Estos son 16 bts'
    iv = b'0123456789ABCDEF'
    cipher = AESImageCipher()
    cipher.setImagePath('images\Imagen3.bmp')
    cipher.setKey(key)
    cipher.setIv(iv)
    cipher.setMode("CBC")
    cipher.encrypt()

    cipher2 = AESImageCipher()
    cipher2.setImagePath('images\Imagen3_eCBC.bmp')
    cipher2.setKey(key)
    cipher2.setIv(iv)
    cipher2.setMode("CBC")
    cipher2.decrypt()

#Modos
#CBC
def cbc_encrypt_decrypt(data, key, iv, mode='cbc'):
    cipher = AES.new(key, AES.MODE_ECB)
    block_size = AES.block_size
    result = bytearray()
    previous_block = iv

    if mode == 'cbc':
        # Encriptación
        data = pad(data, block_size)
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            # XOR con el bloque anterior (IV en el primer bloque)
            block_to_encrypt = xor(block, previous_block)
            encrypted_block = cipher.encrypt(block_to_encrypt)
            result.extend(encrypted_block)
            # Actualiza el bloque anterior
            previous_block = encrypted_block
    else:
        # Desencriptación
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            decrypted_block = cipher.decrypt(block)
            # XOR con el bloque anterior (IV en el primer bloque)
            plaintext_block = xor(decrypted_block, previous_block)
            result.extend(plaintext_block)
            # Actualiza el bloque anterior
            previous_block = block

        result = unpad(result, block_size)

#CFB
def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def cfb_encrypt_decrypt(data, key, iv, mode='cfb'):
    cipher = AES.new(key, AES.MODE_ECB)
    block_size = AES.block_size
    result = bytearray()
    previous_block = iv

    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        # Encriptar o desencriptar el bloque anterior
        encrypted_block = cipher.encrypt(previous_block)
        # XOR con el bloque de texto
        if mode == 'encrypt':
            result.extend(xor(block, encrypted_block[:len(block)]))
        else:
            result.extend(xor(block, encrypted_block[:len(block)]))
        # Actualiza el bloque anterior
        previous_block = encrypted_block
        
        return result
# OFB 
    def xor(a, b):
     return bytes(x ^ y for x, y in zip(a, b))

def ofb_encrypt_decrypt(data, key, iv, mode='ofb'):
    cipher = AES.new(key, AES.MODE_ECB)
    block_size = AES.block_size
    result = bytearray()
    previous_block = iv
    if mode == 'ofb':
        data = pad(data, block_size)

    # Generar el flujo de clave
    for i in range(0, len(data), block_size):
        # Cifra el bloque anterior (o el IV en el primer bloque)
        encrypted_block = cipher.encrypt(previous_block)
        block = data[i:i+block_size]
        # XOR entre el texto y el flujo de clave
        result.extend(xor(block, encrypted_block[:len(block)]))
        # Actualiza el bloque anterior
        previous_block = encrypted_block

    if mode == 'decrypt':
        result = unpad(result, block_size)

   # return bytes(result)
# Operaciones
    def opera(self, state):
        def sub_bytes(self, state):
         for i in range(len(state)):
            for j in range(len(state[i])):
                state[i][j] = sbox[state[i][j]]
                print(f"0x{state[i][j]:02x} ", end="")
            print()
        return state

    def shift_rows(self, state):
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
        for row in state:
            for val in row:
                print(f"0x{val:02x} ", end="")
            print()
        return state

    def mix_columns(self, state):
     """ AES MixColumns transformation """
     for i in range(4):
        s0 = state[i][0]
        s1 = state[i][1]
        s2 = state[i][2]
        s3 = state[i][3]
        state[i][0] = (
            mul(s0, 0x02) ^ mul(s1, 0x03) ^ mul(s2, 0x01) ^ mul(s3, 0x01)
        )
        state[i][1] = (
            mul(s0, 0x01) ^ mul(s1, 0x02) ^ mul(s2, 0x03) ^ mul(s3, 0x01)
        )
        state[i][2] = (
            mul(s0, 0x01) ^ mul(s1, 0x01) ^ mul(s2, 0x02) ^ mul(s3, 0x03)
        )
        state[i][3] = (
            mul(s0, 0x03) ^ mul(s1, 0x01) ^ mul(s2, 0x01) ^ mul(s3, 0x02)
        )
        return state
         
    def add_round_key(self, state, key):
        for i in range(len(state)):
            for j in range(len(state[i])):
                state[i][j] ^= key[i][j]
                print(f"0x{state[i][j]:02x} ", end="")
            print()
        return state
    
    def encr(self):
        if(self.url != None and self.key != None):
            print("Cifrando...")
            img = Image.open(self.url)
            self.image = np.array(img)
            
            self.image_size = img.size
           
            new_url = self.path + self.image_name + "_e" + self.getMode() + "." + self.image_ext

            cipher = None
            if(self.getMode() != "ECB"):
                cipher = AES.new(self.key, self.mode, ive=self.ive)
            else:
                cipher = AES.new(self.key, self.mode)

            state = np.array_split(np.frombuffer(pad(self.image.tobytes(), AES.block_size), dtype=np.uint8), 4)
            round_key = np.array_split(np.frombuffer(self.key, dtype=np.uint8), 4)

            # 10 rondas de AES
            for round in range(10):
                print(f"Ronda {round + 1}:")
                state = self.sub_bytes(state)
                state = self.shift_rows(state)
                if round < 9:
                    state = self.mix_columns(state)
                state = self.add_round_key(state, round_key)

            # Última ronda sin MixColumns
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.add_round_key(state, round_key)    

            ct_bytes = cipher.encrypt(
                pad(
                    self.image.tobytes(),
                    AES.block_size,
                )
            )
            img_data = np.frombuffer(ct_bytes)
            # print(len(img_data))

            image_nva = Image.frombuffer(
                "RGB",
                self.image_size,
                img_data
            )
            image_nva.save(
                new_url
            )
            print("Cifrado")

            # AES Rijndael round constants
            round_constants = (
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
            )
            def key_expansion(key):
              """ AES Key Expansion """
            round_keys = [key]
            for i in range(10):
                prev_key = round_keys[-1]
                new_key = []
                rcon = round_constants[i]
                # Rotate word
                temp = prev_key[1:] + prev_key[:1]
                # SubBytes
                temp = [sbox[b] for b in temp]
                # XOR with Rcon
                temp[0] ^= rcon
                new_key.extend([temp[j] ^ prev_key[j] for j in range(4)])
                # XOR with previous key
                for j in range(1, 4):
                    new_key.extend([new_key[j + 3] ^ prev_key[j + 3]])
                round_keys.append(new_key)
            return round_keys
        
    def mul(a, b):
         """ AES MixColumns multiplication """
         if b == 1:
            return a
         elif b == 2:
            return mul[a]
         elif b == 3:
            return mul[a]
         
    # Impresion de resultado de cada ronda
def print_state(state, imagen, vi):
    return f"{imagen, vi}: {binascii.hexlify(state).decode()}\n"

def aes_encrypt_rounds(plaintext, key):
    key = key.encode('utf-8')
    plaintext = plaintext.encode('utf-8')
    key = key.ljust(16, b'\0')[:16]
    plaintext = pad(plaintext, AES.block_size)
    vi = vi




    
    cipher = AES.new(key, AES.MODE_ECB)
    
    encrypted = b""
    state = plaintext
    output = ""
    
    for i in range(10):  # AES-128 has 10 rounds
        encrypted = cipher.encrypt(state)
        output += print_state(encrypted, f"Round {i + 1} encryption")
        state = encrypted
    
    return output




    # initial_image = Image.open('images\koala.jpg')
    # size_image = initial_image.size
    # data_image = np.array(initial_image)

    # # print(len(data_image))

    # key = b'Estos son 16 bts'
    # iv = b'0123456789ABCDEF'

    # cipher = AES.new(key, AES.MODE_CBC, iv)

    # ct_bytes = cipher.encrypt(pad(data_image.tobytes(), AES.block_size))
    # print("IMG: ", len(data_image.tobytes()))
    # print("ENC: ", len(ct_bytes))
    # img_data = np.frombuffer(ct_bytes)
    # Image.frombuffer("RGB", size_image, img_data).save(
    #     'images\koala_encrypted.png')

    # # ct = b16encode(ct_bytes).decode('utf-8')
    # cipher = AES.new(key, AES.MODE_CBC, iv)
    # print("ENC: ", len(ct_bytes))
    # pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
    # print("PT:  ", len(pt))
    # img_data = np.frombuffer(pt)
    # Image.frombuffer("RGB", size_image, img_data).save(
    #     'images\koala_decrypted.png')
