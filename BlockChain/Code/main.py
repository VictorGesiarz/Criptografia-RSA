import sympy as sp
import time
import hashlib
import random


def timer(func):
    """
    A decorator to measure the execution time of a function.
    Usage: Add @timer above the function definition.
    """
    def wrapper(*args, **kwargs):
        start_time = time.time() 
        result = func(*args, **kwargs)  
        end_time = time.time()  
        print(f"Function '{func.__name__}' took {end_time - start_time:.6f} seconds.")
        return result  
    return wrapper


class rsa_key:
    def __init__(self, bits_modulo=2048, e=2**16+1):
        """
        Generates an RSA key (2048 bits and public exponent 2**16+1 by default)
        """
        self.publicExponent = e

        self.__primeP, self.__primeQ = self.__generate_distinct_primes(bits_modulo)
        self.modulus = self.__primeP * self.__primeQ
        self.__phi_n = (self.__primeP - 1) * (self.__primeQ - 1)

        self.__privateExponent = sp.mod_inverse(self.publicExponent, self.__phi_n)
        self.__privateExponentModulusPhiP = self.__privateExponent % (self.__primeP - 1)
        self.__privateExponentModulusPhiQ = self.__privateExponent % (self.__primeQ - 1)
        self.__inverseQModulusP = sp.mod_inverse(self.__primeQ, self.__primeP)
        
    # def __repr__(self):
    #     string = f'\nP: {self.__primeP}\n\n'
    #     string += f'Q: {self.__primeQ}\n\n'
    #     string += f'Modulus (n): {self.modulus}\n\n'
    #     string += f'D: {self.__privateExponent}\n\n'
    #     return string
    def __repr__(self):
        return str(self.__dict__)
    
    def __generate_distinct_primes(self, bits_modulo):
        """
        We generate P and Q, ensuring that they are distinct
        gcd(e, p-1) = 1 and gcd(e, q-1) = 1  
        """
        a = 2**(bits_modulo//2 - 1)
        b = (2**(bits_modulo//2)) - 1
        
        while True:
            # Generate a random prime p such that gcd(e, p-1) = 1
            primeP = sp.randprime(a, b)
            while sp.gcd(self.publicExponent, primeP - 1) != 1:
                primeP = sp.randprime(a, b)
            
            # Generate a random prime q such that gcd(e, q-1) = 1 and q != p
            primeQ = sp.randprime(a, b)
            while primeQ == primeP or sp.gcd(self.publicExponent, primeQ - 1) != 1:
                primeQ = sp.randprime(a, b)
            
            return primeP, primeQ
    
    def get_public_numbers(self):
        return self.publicExponent, self.modulus

    def sign(self, message):
        """
        Sign the message using RSA with CRT (Chinese Remainder Theorem).
        Output: an integer that is the signature of "message".
        """

        message = message % self.modulus
        
        m1 = pow(message, self.__privateExponentModulusPhiP, self.__primeP) 
        m2 = pow(message, self.__privateExponentModulusPhiQ, self.__primeQ)
        
        h = (self.__inverseQModulusP * (m1 - m2)) % self.__primeP
        signature = (m2 + h * self.__primeQ) % self.modulus
        
        return signature

    def sign_slow(self, message):
        """
        Sign the message using RSA without CRT.
        Output: an integer that is the signature of "message".
        """

        message = message % self.modulus
        signature = pow(message, self.__privateExponent, self.modulus)  # message^d mod n
        return signature


class rsa_public_key:
    def __init__(self, publicExponent=1, modulus=1):
        """
        Genera la clave pública RSA asociada a la clave RSA "rsa_key"
        """
        self.publicExponent = publicExponent
        self.modulus = modulus
        
    # def __repr__(self):
    #     string = f'Public Exponent (e): {self.publicExponent}\n\n'
    #     string += f'Modulus (n): {self.modulus}\n\n'
    #     return string
    def __repr__(self):
        return str(self.__dict__)
    
    def verify(self, message, signature):
        """
        Verifies if the given signature corresponds to the message signed with the associated RSA private key.
        Output:
            - True if "signature" matches the signature of "message" with the public key.
            - False otherwise.
        """

        expected_message = pow(signature, self.publicExponent, self.modulus)
        return expected_message == (message % self.modulus)


class transaction:
    def __init__(self, message=0, RSAkey=0):
        """
        Genera una transacción firmando "message" con la clave "RSAkey"
        """

        self.public_key = None
        self.message = None
        self.signature = None
        if RSAkey != 0: 
            self.initialize(message, RSAkey)

    def initialize(self, message, RSAkey): 
        e, n = RSAkey.get_public_numbers()
        self.public_key = rsa_public_key(e, n)
        self.message = message
        self.signature = RSAkey.sign(message)
        
    # def __repr__(self):
    #     string = f'Public Key:\n- - - - -\n{self.public_key}- - - - -\n\n'
    #     string += f'Message: {self.message}\n\n'
    #     string += f'Signature: {self.signature}\n\n'
    #     return string
    def __repr__(self):
        return str(self.__dict__)
    
    def verify(self):
        """
        Verifies if the signature corresponds to the message using the public key.
        Returns:
            - True if the signature matches the message.
            - False otherwise.
        """
        return self.public_key.verify(self.message, self.signature)
    
    def from_dictionary(self, transaccion):
        self.public_key = rsa_public_key(
            publicExponent = transaccion["public_key"]["publicExponent"],
            modulus = transaccion["public_key"]["modulus"]
        )
        self.message = transaccion["message"]
        self.signature = transaccion["signature"]


class block:
    def __init__(self):
        """
        Creates a block (not necessarily valid).
        """
        self.block_hash = None 
        self.previous_block_hash = None  
        self.transaction = None  
        self.seed = None
        
    # def __repr__(self):
    #     string = f'Block Hash: {self.block_hash}\n\n'
    #     string += f'Previous Block Hash: {self.previous_block_hash}\n\n'
    #     string += f'Seed: {self.seed}\n\n'
    #     string += f'Transaction: \n - - - - - \n{self.transaction} - - - - -\n'
    #     return string
    def __repr__(self):
        return str(self.__dict__)
    
    def genesis(self, transaction):
        """
        Creates the first block in the chain with the given transaction.
        Characteristics:
            - previous_block_hash = 0
            - valid block
        """
        self.previous_block_hash = 0 
        self.transaction = transaction
        self.seed = random.randint(0, int(1e9))  
        self.block_hash = self.compute_hash(self)
        
    def next_block(self, transaction):
        """
        Generates a valid next block with the given transaction.
        """
        next_block = block()
        next_block.previous_block_hash = self.block_hash 
        next_block.transaction = transaction
        next_block.seed = random.randint(0, int(1e9)) 
        next_block.block_hash = next_block.compute_hash(next_block)  
        return next_block

    def compute_hash(self, block):
        """
        Computes the hash of the block using its attributes.
        """
        entrada=str(block.previous_block_hash)
        entrada+=str(block.transaction.public_key.publicExponent)
        entrada+=str(block.transaction.public_key.modulus)
        entrada+=str(block.transaction.message)
        entrada+=str(block.transaction.signature)
        entrada+=str(block.seed)
        h=int(hashlib.sha256(entrada.encode()).hexdigest(),16)
        return h

    def verify_block(self):
        """
        Verifies if the block is valid:
            - Checks that the block's hash matches its content.
            - Checks that the previous block hash is valid.
            - Checks that the transaction is valid.
        """
        # Check if the block's hash matches the recomputed hash
        if self.block_hash != self.compute_hash(self):
            print("Hash incorrecto")
            return False
        
        # Check if the transaction in the block is valid
        if not self.transaction.verify():
            print("Transaccion incorrecta")
            return False
        
        # If genesis block, check special conditions
        if self.previous_block_hash == 0:
            return True

        # Otherwise, check if the previous block hash is valid (non-zero)
        return self.previous_block_hash is not None
    
    def from_dictionary(self, bloque):
        self.block_hash = bloque["block_hash"]
        self.previous_block_hash = bloque["previous_block_hash"]
        transaccion_aux = transaction()
        transaccion_aux.from_dictionary(bloque["transaction"])
        self.transaction = transaccion_aux
        self.seed = bloque["seed"]


class block_chain:
    def __init__(self, transaction=None):
        """
        Creates a blockchain with a list of blocks.
        The first block is the genesis block generated with the transaction "transaction".
        """
        self.list_of_blocks = []
        
        if transaction is not None:
            genesis_block = block()
            genesis_block.genesis(transaction)
            self.list_of_blocks.append(genesis_block)
        else:
            # raise ValueError("Initial transaction must be provided for the genesis block.")
            ...
    
    # def __repr__(self):
    #     return f"<Block Chain with {len(self.list_of_blocks)} blocks>"
    def __repr__(self):
        return str(self.__dict__)
    
    def add_block(self, transaction):
        """
        Adds a valid new block to the chain generated with the transaction "transaction".
        """
        last_block = self.list_of_blocks[-1]
        new_block = last_block.next_block(transaction)
        self.list_of_blocks.append(new_block)
    
    def verify(self):
        """
        Verifies if the blockchain is valid:
            - Checks if all blocks are valid.
            - Checks that the first block is a genesis block.
            - Ensures each block in the chain is properly linked to the next one.
        Output: True if all checks pass; 
                False and the index of the last valid block if a validation fails.
        """
        # Check if the first block is the genesis block
        if not self.list_of_blocks[0].verify_block():
            return False, 0  # Genesis block is invalid
        
        # Verify all blocks in the chain
        for i in range(1, len(self.list_of_blocks)):
            # Check if the current block is valid
            if not self.list_of_blocks[i].verify_block():
                return False, i  # Return the index of the invalid block
            
            # Check that the previous block's hash matches the current block's reference
            if self.list_of_blocks[i].previous_block_hash != self.list_of_blocks[i - 1].block_hash:
                return False, i  # Return the index of the block where the chain breaks
        
        # If all blocks are valid and linked properly
        return True, len(self.list_of_blocks) - 1

    def from_dictionary(self, lista_de_bloques):
        aux = []
        for i in lista_de_bloques['list_of_blocks']:
            bloque = block()
            bloque.from_dictionary(i)
            aux.append(bloque)
        self.list_of_blocks = aux