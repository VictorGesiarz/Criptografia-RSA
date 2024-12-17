from ecpy.curves import Curve, Point
from ecpy.keys import ECPrivateKey, ECPublicKey
from ecpy.ecdsa import ECDSA
import hashlib

# Paso 1: Seleccionar la curva elíptica
cv = Curve.get_curve('secp521r1')

# Paso 2: Generar una clave privada y pública
private_key_value = 1234567890123456789012345678901234567890123456789012345678901234567890  # Ejemplo (puede ser generado aleatoriamente)
private_key = ECPrivateKey(private_key_value, cv)
public_key = private_key.get_public_key()

print("Clave privada:", private_key_value)
print("Clave pública:", (public_key.W.x, public_key.W.y))

# Paso 3: Crear un mensaje y calcular su hash
message = "Este es un mensaje para firmar"
hash_of_message = int.from_bytes(hashlib.sha256(message.encode()).digest(), byteorder='big')

print("Hash del mensaje:", hash_of_message)

# Paso 4: Firmar el hash del mensaje
ecdsa = ECDSA()
signature = ecdsa.sign(
    hash_of_message.to_bytes((hash_of_message.bit_length() + 7) // 8, byteorder='big'),
    private_key
)
print("Firma", signature)



from pyasn1.type import univ, namedtype
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from io import BytesIO

# Define the ASN.1 structure for the ECDSA signature (r, s as integers)
class ECDSASignature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.Integer()),
        namedtype.NamedType('s', univ.Integer())
    )

# Convert the bytearray to a seekable stream
asn1_stream = BytesIO(signature)

# Decode the data
decoded, _ = decode(asn1_stream, asn1Spec=ECDSASignature())

# Extract the r and s values
r = int(decoded['r'])
s = int(decoded['s'])
signature_tuple = (r, s)

# Print the r and s values
print(f"r: {r}")
print(f"s: {s}")


signature_recreated = ECDSASignature()
signature_recreated['r'] = r
signature_recreated['s'] = s
signature_recreated = encode(signature_recreated)
print("Encoded ASN.1 DER signature:", signature_recreated)



# Paso 5: Verificar la firma
is_valid = ecdsa.verify(
    hash_of_message.to_bytes((hash_of_message.bit_length() + 7) // 8, byteorder='big'),
    signature_recreated,
    public_key
)

if is_valid:
    print("La firma es válida: CIERTO")
else:
    print("La firma es inválida: FALSO")
