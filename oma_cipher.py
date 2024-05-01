#! /usr/bin/env python3

from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import InvalidToken
import tkinter as tk

# @TODO should i rewrite this in Qt?

def decodierung(passwd, filename):
    print("*******   Entschlüssulung von "+ filename + "     ***************\n")
    print("Decrypting file with Fernet AES CBC")
    # Fernet object mit key anlegen
    f_token = Fernet(key_gen(passwd))

    with open(filename, 'rb') as file:
        data = file.read()
    # schon byte aus datei data.encode()

    print("Verschlüsselte Daten geladen ")

    try:
        dec_data = f_token.decrypt(data)
        with open(filename, 'wb') as file:
            file.write(dec_data)
            print("File: "+ filename + " Decoded")
            #top.quit()
    except InvalidToken:
        print("Falsches Passwort! ")


def encodierung(passwd, filename):
    print("*******   Verschlüssulung von "+ filename + "     ***************\n")
    print("Encrypting file with Fernet AES CBC")
    # Fernet object mit key anlegen
    f_token = Fernet(key_gen(passwd))
    with open(filename, 'rb') as file:
        data = file.read()
    # schon byte aus datei data.encode()

    print("Unschlüsselte Daten geladen ")
    try:
        enc_data = f_token.encrypt(data)
        with open(filename, 'wb') as file:
            file.write(enc_data)
            print("File: "+ filename + " encoded")
            #top.quit()
    except InvalidToken:
        print("Falsches Passwort! ")





def key_gen(passwd):
    # gibt key aus
    with open("salt.key", 'rb') as file:
        # salt auslesen
        # wurde aus os.urandom(16) generiert
        salt = file.readline()
        print(b"Salt: " + salt)



    # kdf = key derivation function
    # mehr keys von masterkey erzeugen
    #Funktionsparameter festlegen
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
        backend = default_backend()
        )
    # key mit passwort erzeugen
    key = base64.urlsafe_b64encode(kdf.derive(passwd.encode()))
    print (b"Key: " + key)
    # Bei gleichem (richtigem) Passwort und Salt immer gleicher Key!
    # muss von standart char umgewandelt werden
    # ohne parameter nach UTF-8 in Bytecode d.h. pro Byte ein Charakter
    # Strings sind im Speicher nicht direkt als Bytecode auslesbar
    return key

def button_decrypt():
    filename = x.get()
    passwd = q.get()
    print("Dateiname: " + filename)
    print("Passwort: " + passwd)
    decodierung(passwd, filename)
    encryption_status.config(text=f"Daten sind entschlüsselt!", bg="red")

def button_encrypt():
    filename = x.get()
    passwd = q.get()
    print("Dateiname: " + filename)
    print("Passwort: " + passwd)
    encodierung(passwd, filename)
    encryption_status.config(text=f"Daten sind verschlüsselt!", bg="cyan")

if __name__ == "__main__":

    top = tk.Tk()
    top.title("Datensicherheit bei Oma")
    top.geometry("500x300+" + str(int((top.winfo_screenwidth()-500)/2)) + "+" + str(int((top.winfo_screenheight()-300)/2)))
    top['bg'] = "white"

    frame = tk.Frame(top)
    frame.grid()


    w = tk.Label(top, bg="white", fg="black", text="Dateiname")
    x = tk.Entry(top, bg="white", fg="black", text="Dateiname:")
    p = tk.Label(top, bg="white", fg="black", text="Passwort")
    q = tk.Entry(top, bg="white", fg="black", text="Passwort:", show="*")
    y = tk.Button(top, bg="grey", height=2, width=15, text="Decrypt", command=button_decrypt)
    z = tk.Button(top, bg="green", height=2, width=15, text="Encrypt", command=button_encrypt)
    r = tk.Label(top, bg="white", fg="red", text="Daten nach laden im Browser direkt wieder verschlüsseln!")


    encryption_status = tk.Label(top, bg="cyan", fg="black", text=f"Daten sind verschlüsselt.")




    w.grid(columnspan=3, row=0)
    x.grid(columnspan=3, row=0, column=3)
    p.grid(columnspan=3, row=1)
    q.grid(columnspan=3, row=1, column=3)
    y.grid(columnspan=3, row=2)
    z.grid(columnspan=3, row=2, column=3)
    r.grid(columnspan=6, row=3)

    encryption_status.grid(columnspan=6, row=4)
    top.mainloop()
