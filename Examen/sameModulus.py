from math import gcd
from sympy import mod_inverse

def common_modulus_attack(c1, c2, e1, e2, n):
    """
    Perform the common modulus attack to recover the original message.
    
    Args:
        c1 (int): Ciphertext encrypted with public key e1.
        c2 (int): Ciphertext encrypted with public key e2.
        e1 (int): Public exponent of the first user.
        e2 (int): Public exponent of the second user.
        n (int): Shared modulus.
        
    Returns:
        int: The decrypted original message.
    """
    # Ensure e1 and e2 are coprime
    if gcd(e1, e2) != 1:
        raise ValueError("e1 and e2 must be coprime for this attack to work.")
    
    # Extended Euclidean Algorithm to find a and b
    a, b, _ = extended_gcd(e1, e2)
    
    # If b is negative, compute modular inverse of c2
    if b < 0:
        c2 = mod_inverse(c2, n)
        b = -b
    
    # Compute the original message
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m

def extended_gcd(a, b):
    """Extended Euclidean Algorithm to find coefficients a, b such that a*x + b*y = gcd(x, y)."""
    if b == 0:
        return (1, 0, a)
    x1, y1, gcd = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return (x, y, gcd)

# Example usage
if __name__ == "__main__":
    n = 170538320697436872549809649066816068525278315503585613616926600658279661841794052814556310517678241518461467436380671665425021924276297381700142880232528452054970212543680296514864304929580458367386643270944790798417254655492298435638635963807216643697407017271104923429535053148910544192213065464757330795991
    
    # User A
    e1 = 631   
    c1 = 143648910760608541629655797863669233249654290192667946449353863958718782714466913671809733769863151633971910117649232741134345266577856389088427448917448410834321695399557954613004302086099726507346203118256286782283363963612698368541323343424249017272433470667797237669747178579607409233975301057631819285331

    # User B
    e2 = 419   
    c2 = 76253833939695580915043884230689522837459339989253913296900449103458516804925477653246549436825807710527383835373924232343152282510426950888503598042316911900489760021159070955189673766986093870581802468375295538753692677065391430507487638986710818627192198957468318822117728898517948974739108685564351309302  
    
    # Decrypt the original message
    m = common_modulus_attack(c1, c2, e1, e2, n)
    print(f"\nOriginal message:\n\n{m}\n")