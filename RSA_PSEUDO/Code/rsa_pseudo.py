import os
import sympy as sp

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

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

name = "huilin.ni"
n = modulus_dict[name]
n_bin = bin(n)[2:]

# len(n) = 2048, len(p) y len(q) = 1024
# len(r) y len(s) = 512 --> 1/4 parte de la long de n
partition_length = len(n_bin)//4

# Partimos la cadena binaria en 4 partes
part1 = n_bin[:partition_length] # Primera mitad de r * s
part2 = n_bin[partition_length:partition_length*2] # Segunda mitad de r * s * (r^2 + s^2)
part3 = n_bin[partition_length*2:partition_length*3] # Primera mitad de r * s * (r^2 + s^2)
part4 = n_bin[partition_length*3:] # Segunda mitad de r * s

# Convertimos cada parte a entero
part1_int = int(part1, 2)
part2_int = int(part2, 2)
part3_int = int(part3, 2)
part4_int = int(part4, 2)

print(part1_int)