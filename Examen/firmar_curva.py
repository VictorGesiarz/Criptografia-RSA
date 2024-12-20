from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey
from ecpy.ecdsa import ECDSA

# Datos proporcionados
public_key_tuple = (
    183746701883757124826755524715142517173684662596382931014900106779410231692051781676595944589173697763631191386590655544007103631661168945042439908049126628,
    1601281877710170848847338512967691812903583180826685392300517340541208413570012609627603954169927449316111853622325474586718412581245331911174500642483080471
)
hash_of_document = int(
    "5572218363369325710622755349080158642966138912594496268137619782031501993116570169733490485653610033368823165157382759353621377017869899053722083617134315051"
)
signature_tuple = (
    636209411702914270661152765691119681822202526214190888223313780804486620649417809538075073320536552396577393606651565148805816715408423177786550261549407061,
    5665944802029951168612385975560511149978964867796618009229554554695039618868560857058585498994051253971070241725582009074416192241470619741064412300461145432
)


from pyasn1.type import univ, namedtype
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from io import BytesIO

class ECDSASignature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.Integer()),
        namedtype.NamedType('s', univ.Integer())
    )
signature_recreated = ECDSASignature()
signature_recreated['r'] = signature_tuple[0]
signature_recreated['s'] = signature_tuple[1]
signature_recreated = encode(signature_recreated)
print("Encoded ASN.1 DER signature:", signature_recreated)


# Definir la curva utilizada (NIST P-521)
cv = Curve.get_curve('secp521r1')

# Construir la clave pública
public_key = ECPublicKey(Point(public_key_tuple[0], public_key_tuple[1], cv))

# Inicializar ECDSA
ecdsa = ECDSA()

# Verificar la firma
try:
    is_valid = ecdsa.verify(
        hash_of_document.to_bytes((hash_of_document.bit_length() + 7) // 8, byteorder='big'),  # Hash del documento en bytes
        signature_recreated,  # Firma como una tupla (r, s)
        public_key  # Clave pública
    )
    if is_valid:
        print("La firma es válida: CIERTO")
    else:
        print("La firma es válida: FALSO")
except Exception as e:
    print(f"Error al verificar la firma: {e}")
    print("La firma es válida: FALSO")
