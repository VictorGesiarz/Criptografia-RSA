
class block:
    def __init__(self):
        """
        Crea un bloque (no necesariamente válido)
        """
        self.block_hash
        self.previous_block_hash
        self.transaction
        self.seed
        
    def __repr__(self):
        return str(self.__dict__)
    
    def genesis(self, transaction):
        """
        Genera el primer bloque de una cadena con la transacción "transaction"
        que se caracteriza por:
            - previous_block_hash=0
            - ser válido
        """
        
    def next_block(self, transaction):
        """
        Genera un bloque válido seguiente al actual con la transacción "transaction"
        """
        
    def verify_block(self):
        """
        Verifica si un bloque es válido:
            - Comprueba que el hash del bloque anterior cumple las condiciones exigidas
            - Comprueba que la transacción del bloque es válida
            - Comprueba que el hash del bloque cumple las condiciones exigidas
        Salida: el booleano True si todas las comprobaciones son correctas;
                el booleano False en cualquier otro caso.
        """


class block_chain:
    def __init__(self, transaction):
        """
        Genera una cadena de bloques que es una lista de bloques,
        el primer bloque es un bloque "genesis" generado amb la transacción "transaction"
        """
        self.list_of_blocks
        
    def __repr__(self):
        return str(self.__dict__)
    
    def add_block(self, transaction):
        """
        Añade a la cadena un nuevo bloque válido generado con la transacción "transaction"
        """
        
    def verify(self):
        """
        Verifica si la cadena de bloques es válida:
            - Comprueba que todos los bloques son válidos
            - Comprueba que el primer bloque es un bloque "genesis"
            - Comprueba que para cada bloque de la cadena el siguiente es correcto
        Salida: el booleano True si todas las comprobaciones son correctas;
                en cualquier otro caso, el booleano False y un entero
                correspondiente al último bloque válido
        """

        
        
class transaction:
    def __init__(self, message, RSAkey):
        """
        Genera una transacción firmando "message" con la clave "RSAkey"
        """
        self.public_key
        self.message
        self.signature
        
    def __repr__(self):
        return str(self.__dict__)
    
    def verify(self):
        """
        Salida: el booleano True si "signature" se corresponde con la
                firma de "message" hecha con la clave RSA asociada a la clave
                pública RSA;
                el booleano False en cualquier otro caso.
        """
        
class rsa_key:
    def __init__(self, bits_modulo=2048, e=2**16+1):
        """
        Genera una clave RSA (de 2048 bits y exponente público 2**16+1 por defecto)
        """
        self.publicExponent
        self.privateExponent
        self.modulus
        self.primeP
        self.primeQ
        self.privateExponentModulusPhiP
        self.privateExponentModulusPhiQ
        self.inverseQModulusP
        
    def __repr__(self):
        return str(self.__dict__)
    
    def sign(self, message):
        """
        Salida: un entero que es la firma de "message" hecha con la clave RSA usando el TCR
        """
        
    def sign_slow(self, message):
        """
        Salida: un entero que es la firma de "message" hecha con la clave RSA sin usar el TCR
        """


class rsa_public_key:
    def __init__(self, rsa_key):
        """
        Genera la clave pública RSA asociada a la clave RSA "rsa_key"
        """
        self.publicExponent
        self.modulus
        
    def __repr__(self):
        return str(self.__dict__)
    
    def verify(self, message, signature):
        """
        Salida: el booleano True si "signature" se corresponde con la
                firma de "message" hecha con la clave RSA asociada a la clave
                pública RSA;
                el booleano False en cualquier otro caso.
        """
