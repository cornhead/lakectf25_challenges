#!/usr/bin/python3

flag = os.getenv('FLAG', 'CTF{dummyflag}')

p = 2**255 - 19
A = 486662
B = 1
base = 9
q = 2**252



# The finite field of integers modulo p (GF is short for Galois Field)
field = GF(2^255 - 19)
# EllipticCurve(field, [a1, a2, a3, a4, a5]) constructs an elliptic curve over the
# given field, with curve equation y^2 + a1*x*y + a3*y = x^3 + a2*x^2 + a4*x + a5.
# We choose a1 = 0, a2 = 486662, a3 = 0, a4 = 1, a5 = 0 to give us the Montgomery
# curve equation y^2 = x^3 + 486662 * x^2 + x.
E = EllipticCurve(field, [0, 486662, 0, 1, 0])
# Check the order (cardinality) of the group defined by that curve
q = 2^252 + 27742317777372353535851937790883648493
q.is_prime() # returns True
E.cardinality() == 8 * q # returns True
# Define the base point (generator) g to be the point with x coordinate = 9,
# and check the order of that point
base = 9
g = [field(base), sqrt(field(base^3 + 486662 * base^2 + base))] # [x, y] coordinates
q * E(g) # returns (0 : 1 : 0), which is the point at infinity
# This indicates that point g has order q in the elliptic curve group E
