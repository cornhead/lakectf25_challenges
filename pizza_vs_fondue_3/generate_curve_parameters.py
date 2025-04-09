from sage.all import *

from secrets import randbelow


# ------------- General Parameters for Curve25519 -----------------
# https://www.cl.cam.ac.uk/teaching/2122/Crypto/curve25519.pdf

# The finite field of integers modulo p (GF is short for Galois Field)
p = 2**255 - 19
field = GF(p)
# EllipticCurve(field, [a1, a2, a3, a4, a5]) constructs an elliptic curve over the
# given field, with curve equation y^2 + a1*x*y + a3*y = x^3 + a2*x^2 + a4*x + a5.
# We choose a1 = 0, a2 = 486662, a3 = 0, a4 = 1, a5 = 0 to give us the Montgomery
# curve equation y^2 = x^3 + 486662 * x^2 + x.
E = EllipticCurve(field, [0, 486662, 0, 1, 0])
# Check the order (cardinality) of the group defined by that curve
q = 2**252 + 27742317777372353535851937790883648493
# q.is_prime() # returns True
assert E.cardinality() == 8 * q # returns True
# Define the base point (generator) g to be the point with x coordinate = 9,
# and check the order of that point
base = 9
g = [field(base), sqrt(field(base**3 + 486662 * base**2 + base))] # [x, y] coordinates
# This indicates that point g has order q in the elliptic curve group E


# ------------ Find Point of Order 2 -----------------

current_order = 0
while current_order != 4*q:
    G = E.random_element()
    current_order = G.order()
    # print(current_order == q, current_order)

# print(G)

# ---------------- Print Parameters -------------------

print(f'p = {p}')
print(f'field = GF(p)')
print(f'E = EllipticCurve(field, [0, 486662, 0, 1, 0])')
print(f'q = 2**252 + 27742317777372353535851937790883648493')
print(f'assert E.cardinality() == 8 * q')
# print(f'base = 9')
# print(f'g = [field(base), sqrt(field(base**3 + 486662 * base**2 + base))]')
print(f'G = E([{G.xy()[0]}, {G.xy()[1]}])')

# ------------------- Check if attack works ------------

print('\n')

x = randbelow(q)
y = randbelow(q)

K = x*y*G
K_prime = q*K

print(K)
print(K_prime)
print(K_prime.order())
assert 4*K_prime == K_prime

roots = E.torsion_polynomial(4).roots(multiplicities=True)
print(roots)
for r, m in roots:
    try:
        print(E.lift_x(r))

        if r != 0:
            for i in range(4):
                print(i*E.lift_x(r))
    except:
        print('failed to lift x')
