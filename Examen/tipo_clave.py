from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Cargar el certificado en formato PEM
def load_certificate(file_path):
    with open(file_path, 'rb') as cert_file:
        pem_data = cert_file.read()
        return x509.load_pem_x509_certificate(pem_data)

# Determinar el tipo de clave pública
def get_key_type(cert):
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_size = public_key.key_size
        return f"RSA-{key_size}"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve = public_key.curve.name
        if curve == "secp256r1":
            return "ECC-256"
        elif curve == "secp384r1":
            return "ECC-384"
        elif curve == "secp521r1":
            return "ECC-521"
        else:
            return f"Unknown ECC Curve: {curve}"
    else:
        return "Unknown Key Type"

def get_common_name(cert):
    # Extraer el Common Name (CN)
    subject = cert.subject
    cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return cn[0].value if cn else "CN no encontrado"

def get_first_10_digits(cert):
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        # Extraer el módulo para RSA y obtener los primeros 10 dígitos
        modulus = public_key.public_numbers().n
        return str(modulus)[:10]
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        # Extraer la componente x para ECC y obtener los primeros 10 dígitos
        x_coordinate = public_key.public_numbers().x
        return str(x_coordinate)[:10]
    else:
        return "Clave no soportada"
    
    
# Ruta al certificado
certificate_path = "./Examen/certificado.pem"

# Cargar y analizar el certificado
certificate = load_certificate(certificate_path)
key_type = get_key_type(certificate)
print(f"El tipo de clave es: {key_type}")

cn = get_common_name(certificate)
first_10_digits = get_first_10_digits(certificate)

print(f"Common Name (CN): {cn}")
print(f"Primeros 10 dígitos del módulo o componente x: {first_10_digits}")