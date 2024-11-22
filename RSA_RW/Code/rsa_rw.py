
"""

En Atenea encontraréis directorio RSA_RW donde hay una serie de ficheros del tipo:
    - nombre.apellido_AES.enc que es el resultado de cifrar un fichero determinado con la clave K
    - nombre.apellido_RSA_RW.enc que es el resultado de cifrar la clave K con la clave pública RSA 
    que se encuentra en el fichero nombre.apellido_pubkeyRSA_RW.pem.

El fichero cifrado se ha obtenido usando el comando:
    > openssl enc -e -aes-128-cbc -pbkdf2 -kfile fichero.key -in fichero.txt -out fichero.enc
El fichero fichero.key que contiene la clave se ha cifrado con el comando:
    > openssl pkeyutl -encrypt -inkey pubkeyRSA.pem -pubin -in fichero.txt -out fichero.enc

openssl est ́a disponible en https://www.openssl.org. Se instala por defecto en la mayoría de las 
distribuciones de Linux, por ejemplo en la imagen Linux de la FIB.

-- ENUNCIADO --
Del fichero nombre.apellido_pubkeyRSA_RW.pem hay que extraer la clave pública (openssl puede ayudar),
factorizar el módulo, calcular la clave privada, escribirla en un fichero en formato PEM (puede ser útil la
biblioteca Crypto.PublicKey.RSA de python) aunque podéis encontrar otras para cualquier lenguaje de
vuestra preferencia) y, para acabar, descifrar el fichero usando openssl

"""

name = "huilin.ni"
# name = "victor.gesiarz"

