from sympy import cbrt, root, mod_inverse

def chinese_remainder_theorem(remainders, moduli):
    """
    Solve the Chinese Remainder Theorem for given remainders and moduli.
    
    Args:
        remainders (list): List of remainders [c1, c2, ..., ck].
        moduli (list): List of moduli [n1, n2, ..., nk].
    
    Returns:
        int: The solution x such that x ≡ c_i (mod n_i) for all i.
    """
    N = 1
    for n in moduli:
        N *= n
    
    x = 0
    for ci, ni in zip(remainders, moduli):
        Ni = N // ni
        Mi = mod_inverse(Ni, ni)
        x += ci * Mi * Ni
    
    return x % N

def find_original_message(c_list, n_list, e):
    """
    Perform Håstad's Broadcast Attack to recover the original message.
    
    Args:
        c_list (list): List of ciphertexts [c1, c2, ..., ck].
        n_list (list): List of moduli [n1, n2, ..., nk].
        e (int): Public exponent (common for all users).
    
    Returns:
        int: The decrypted original message.
    """
    # Step 1: Solve the system of congruences using CRT
    m_e = chinese_remainder_theorem(c_list, n_list)
    
    # Step 2: Take the e-th root of the result to recover m
    m = int(root(m_e, e))  # sympy's root function to compute e-th root
    return m

# Example usage
if __name__ == "__main__":
    # Example inputs
    n_list = [
        # Modulus for user A
        11704458880696591489703356592616416025127868098410953766007322413765303922671395383720842616703077269781776882240487,   
        # Modulus for user B
        17234261282515109030920373387929821699941371306961933980268800658182839692020822375533773555017682851968911081539163,   
        # Modulus for user C
        19053471012090780990243272591945771901765983282293268088579846661520394095256752218097009967231753236434269475701791,  
        # Modulus for user D
        22610770261657789496058163182213778222550168328189289540160032215867782655240728693716233181590330679713873208985719,  
        # Modulus for user E
        21950753793319115751513988943054963225104568326742396944258659289484943230064914465252162060935004886578442146573447   
    ]
    c_list = [
        # Ciphertext for user A
        2381135004837897289190972124556231417118807930731324069160257956664435609464314385680469250470620831138095008900646,   
        # Ciphertext for user B
        2499873093349932324023281425895296431137480523032368295855507740581860865528598028799191990665092208197509522428214,   
        # Ciphertext for user C
        3632473745988792738802194052469335467505548049564875725126918423915403348043645271089535418777120141385580888901037,   
        # Ciphertext for user D
        1409220620617001057501573888283159677104961770966421376214595069656842417134099099261984297868300102501573653994925,   
        # Ciphertext for user E
        12270886775846611899442389328947778782582612652536625498026593376049816567444568574813082551421753150567283738309639   
    ]
    e = 5  # Public exponent (shared by all users)
    
    # Recover the original message
    m = find_original_message(c_list, n_list, e)
    print(f"\nOriginal message:\n\n{m}\n")