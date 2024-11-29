import os
import sympy as sp

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from math import sqrt
from decimal import Decimal, getcontext

"""
En Atenea también encontraréis el directorio RSA pseudo donde hay una serie de ficheros semejantes a los
anteriores.

Ahora el módulo público es un entero n = p q con p y q tales que si en o p es la concatenación de r y
s de exactamente la mitad de bits de p, entonces q es, en binario, la concatenación de s y r. O sea que si
p = r||s, entonces q = r||s con #bits(r) = #bits(s) = 1/2#bits(p) = 1/2#bits(q).

Del fichero nombre.apellido pubkeyRSA pseudo.pem hay que extraer la clave pública, factorizar el módulo,
calcular la clave privada, escribirla en un fichero en format PEM y descifrar el fichero usando openssl.
"""

modulus_dict = {}
EXPONENT = 0

# Ruta de la carpeta a recorrer
carpeta = "./RSA_PSEUDO/"

for archivo in os.listdir(carpeta):
    if archivo.endswith(".pem"):
        with open(carpeta + archivo, "rb") as pem_file: 
            data = pem_file.read()

        public_key = serialization.load_pem_public_key(data, backend=default_backend())

        # Extract modulus and public exponent
        if isinstance(public_key, rsa.RSAPublicKey):
            numbers = public_key.public_numbers()
            modulus = numbers.n
            exponent = numbers.e
            name = archivo.split("_")[0]
            modulus_dict[name] = modulus
        
            if EXPONENT == 0: 
                EXPONENT = exponent
            elif EXPONENT != 0 and exponent != EXPONENT:
                raise ValueError(f"The exponent of one of the users is different from the rest:\n user: \
                                {name}, exponent: {exponent} \n another exponent: {EXPONENT}")


names = ['huilin.ni', 'victor.gesiarz']

getcontext().prec = 1024
for name in names:

    print("\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
    print(f"FACTORING OF {name}'s MODULE.")
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
    
    n_original = modulus_dict[name]
    n_bin = bin(n_original)[2:]

    length = len(n_bin)
    if length != 2048: 
        print(f"\nModulus has a size {len(n_bin)}, which is smaller than 2048. \
                \nProceeding to add 0 padding to the left.")
        padding_length = 2048 - len(n_bin)
        if padding_length < 0: 
            raise ValueError(f"\nModulus has a size {len(n_bin)}, which is bigger than 2048.")
        padding = "0" * padding_length
        n_bin = padding + n_bin

    # len(n) = 2048, len(p) y len(q) = 1024
    # len(r) y len(s) = 512 --> 1/4 parte de la long de n
    partition_length = len(n_bin) // 4

    # Partimos la cadena binaria en 4 partes
    part1 = n_bin[:partition_length] # Primera mitad de r * s
    part2 = n_bin[partition_length:partition_length*2] # Segunda mitad de r * s * (r^2 + s^2)
    part3 = n_bin[partition_length*2:partition_length*3] # Primera mitad de r * s * (r^2 + s^2)
    part4 = n_bin[partition_length*3:] # Segunda mitad de r * s


    for combination in range(1, 3):

        rs_l = part1
        rs_r = part4
        
        rs_l_minus_c = int(rs_l, 2) - combination 
        rs_l_minus_c_bin = bin(rs_l_minus_c)[2:]

        if length != 2048:
            rs_l_minus_c_bin = padding + rs_l_minus_c_bin

        r_s = int(rs_l_minus_c_bin + rs_r, 2)

        middle = bin(combination)[2:] + (part2+part3)
        s_r = int(rs_r + rs_l_minus_c_bin, 2)
        r2_s2 = int(middle, 2) - s_r

        x = Decimal(r_s)
        y = Decimal(r2_s2)

        discriminant = y**2 - 4*x**2
        if discriminant < 0: 
            continue

        t = (y + discriminant.sqrt()) // 2
        r = t.sqrt()
        s = r_s // r

        r_bin = bin(int(r))[2:]
        s_bin = bin(int(s))[2:]
        p_bin = r_bin + s_bin
        q_bin = s_bin + r_bin
        p = int(p_bin, 2)
        q = int(q_bin, 2)
        n = p * q 

        if n == n_original: 
            print("\n---- P and Q FOUND! p * q = modulus correctly calculated ----\n")
            break

    print(f'For user {name}:\n    - P: {p}\n    - Q: {q}\n')


    # ---------- Cálculo clave privada ----------
    phi_n = (p-1) * (q-1)
    d = sp.mod_inverse(EXPONENT, phi_n)
    print(f'The private exponent of this user is: {d}\n')

    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = sp.mod_inverse(q, p)

    private_key = rsa.RSAPrivateNumbers(
        p = p, q = q, d = d, dmp1 = dmp1, dmq1 = dmq1, iqmp = iqmp, 
        public_numbers = rsa.RSAPublicNumbers(EXPONENT, n)
    ).private_key(default_backend())

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(carpeta + name + '_privatekeyRSA_pseudo.pem', 'wb') as pem_file:
        pem_file.write(pem)

    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n")


# Comanda openssl para descifrar la clave cifrada del AES:
# openssl pkeyutl -decrypt -inkey huilin.ni_privatekeyRSA_pseudo.pem -in huilin.ni_RSA_pseudo.enc -out huilin.ni_AES_key.txt
# openssl pkeyutl -decrypt -inkey victor.gesiarz_privatekeyRSA_pseudo.pem -in victor.gesiarz_RSA_pseudo.enc -out victor.gesiarz_AES_key.txt

# Comanda openssl para descifrar el archivo cifrado con AES: 
# openssl enc -d -aes-128-cbc -pbkdf2 -kfile huilin.ni_AES_key.txt -in huilin.ni_AES_pseudo.enc -out huilin.ni_decrypted_file.png
# openssl enc -d -aes-128-cbc -pbkdf2 -kfile victor.gesiarz_AES_key.txt -in victor.gesiarz_AES_pseudo.enc -out victor.gesiarz_decrypted_file.png
