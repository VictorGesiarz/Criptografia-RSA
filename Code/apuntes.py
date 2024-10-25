import math 


class RSA:
    def __init__(self, public_exp, private_exp) -> None:
        self.e = public_exp
        self.p, self.q = None # Primos (mismo nº bits) Se generan aleatoriamente asegurandonos de que el numero de bits es el que queremos. 
        self.d = private_exp # Con los p y q generados calculamos el inverso modular y si da 1 perfecto, si no cogemos otros, y repetimos to el rato
        self.n = self.p * self.q # Con los p y q correctamente creados creamos la n y podemos eliminar la p y la q. 
        
        """
        inverso modular
        phi = (p-1)(q-1)
        d * e = 1 mod phi
        
        - solo existe si mcd(e, phi) = 1
        - identidad de Bezout: existen r, s tal que: 
            e * r + phi * s = 1
            como lo miramos modulo phi: phi * s = 0
            entonces e * r = 1 mod phi
        
        inverso de e mod phi = int(gcdex(e, phi)[0] % phi) | con simpy: mod_inverse(e, phi) y lo da directamente bien
        """

class Block:
    def __init__(self) -> None:
        pass
        
# math.gcd()
# r, s, mcd = math.gcdex() Devuelve también los componentes de la entidade de Bezout. 

"""

m = mensaje (entero)
Public_key 
Firmar: S = m^d mod n
    
    - FIRMA LENTA = math.pow(m, d, n)
    
    - FIRMA RAPIDA (CRT): Teorema chino de los restos
        Objetivo: calcular x mod p*q
        Calculamos 
            x mod p = a 
            x mod q = b
            (reducimos el numero de bits a la mitad para cada operacion y calcular el modulo con primos es mucho mas rapido)
            
        Entonces: 
            x = a*q*q' + b*p*p' (donde q*q' = 1 mod p y p*p' = 1 mod q)
            
            
Teorema de Fermat para hacer pow(m, d, p) 
x ^ (p-1) = 1 (p)

entonces
    pow(m, d, p) = pow(m, d mod(p-1), p)

"""


class BlockChain: 
    def __init__(self) -> None:
        pass