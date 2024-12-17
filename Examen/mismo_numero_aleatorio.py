from ecpy.curves import Curve
from sympy import mod_inverse

# Definir la curva SECP384r1
curve = Curve.get_curve('secp384r1')

# Hashes de los mensajes
H1 = 0x8708878e50041df55aeaf58e1ee03dc723aab45d36d47f4e1d49597b35aa6eb2f29b815b3131a4d8225610e909c4ca2f
H2 = 0x47147e25d90562e96e978cff70ff1c208a482c28ebcc45d3552d62d4eb65c45ed0a7ed1b1c8f998ad9a7240e9bf12e9

# Firmas
r = 18729973679190817623118111313771828863663483513774837152408759700444959675380395484441782281088986325568028125572313
s1 = 20359314114894398883483580278464256322867251438942572866576324564009786523201552170100051340293096655180830624945318
s2 = 33549408991998253599552853970526509375371474724984217940328017323799040205020694232660707492411777350321253243465321


n = curve.order

# Calcular k usando las dos firmas
k = ((H1 - H2) * mod_inverse(s1 - s2, n)) % n
print(f"Valor de k: {k}")

# Calcular la clave privada d
d = ((s1 * k - H1) * mod_inverse(r, n)) % n
print(f"Clave privada: {d}")
