import os
import sympy as sp

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


modulus_dict = {}
EXPONENT = 0

# Ruta de la carpeta a recorrer
carpeta = "./RSA_RW/RSA_RW/"

# Recorrer los archivos en la carpeta
for archivo in os.listdir(carpeta):
    if archivo.endswith(".pem"):

        with open(carpeta + archivo, "rb") as pem_file:
            key_data = pem_file.read()
        
        # Load the public key
        public_key = serialization.load_pem_public_key(key_data, backend=default_backend())

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


# Selección del usuario
names = ["huilin.ni", "victor.gesiarz"]  

for name in names: 
    my_modulus = modulus_dict[name]
    print(f'The modulus of {name} is: \n\n{my_modulus}.\n')

    print('The users you share primes with are:\n')
    primes = []
    for n, modulus in modulus_dict.items():
        if n == name: continue
        
        gcd = sp.gcd(modulus, my_modulus)
        if gcd != 1: 
            print(f'  - {n}: {modulus}')
            primes.append(int(gcd))
    print()
    p = primes[0]
    q = primes[1]

    phi_n = (p-1) * (q-1)
    d = sp.mod_inverse(EXPONENT, phi_n)
    print(f'The private exponent of this user is: {d}\n')

    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = sp.mod_inverse(q, p)

    private_key = rsa.RSAPrivateNumbers(
        p = p, q = q, d = d, dmp1 = dmp1, dmq1 = dmq1, iqmp = iqmp, 
        public_numbers = rsa.RSAPublicNumbers(EXPONENT, my_modulus)
    ).private_key(default_backend())

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(carpeta + name + '_privatekeyRSA_RW.pem', 'wb') as pem_file:
        pem_file.write(pem)

    print("\n - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n")


# Comanda openssl para descifrar la clave cifrada del AES:
# openssl pkeyutl -decrypt -inkey huilin.ni_privatekeyRSA_RW.pem -in huilin.ni_RSA_RW.enc -out huilin.ni_AES_key.txt
# openssl pkeyutl -decrypt -inkey victor.gesiarz_privatekeyRSA_RW.pem -in victor.gesiarz_RSA_RW.enc -out victor.gesiarz_AES_key.txt

# Comanda openssl para descifrar el archivo cifrado con AES: 
# openssl enc -d -aes-128-cbc -pbkdf2 -kfile huilin.ni_AES_key.txt -in huilin.ni_AES_RW.enc -out huilin.ni_decrypted_file.png
# openssl enc -d -aes-128-cbc -pbkdf2 -kfile victor.gesiarz_AES_key.txt -in victor.gesiarz_AES_RW.enc -out victor.gesiarz_decrypted_file.png