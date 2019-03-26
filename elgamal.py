from random import randint as rnd
from datetime import datetime as dt
import math, json


# Public and Private key Object
class PubKey(object):
  def __init__(self, y=None, g=None, p=None):
    self.y = y
    self.g = g
    self.p = p

class PrivKey(object):
  def __init__(self, x=None, p=None):
    self.x = x
    self.p = p


# Find Prime things
def findPrime():
  bit = 256
  while(1):
    p = rnd(2**(bit-2), 2**(bit-1))
    while(p % 2 == 0): p = rnd(2**(bit-2), 2**(bit-1))
    while(not isPrime(p)):
      p = rnd(2**(bit-2), 2**(bit-1))
      while(p % 2 == 0): p = rnd(2**(bit-2), 2**(bit-1))
    p = p * 2 + 1
    if isPrime(p): return p

def isPrime(n):
  for i in range(32):
    a = rnd(1, n-1)
    if gcd(a, n) > 1: return False
    if not jacobi(a, n) % n == pow(a, (n-1)//2, n): return False
  return True

def gcd(a, b):
  while b != 0: c = a % b; a = b; b = c
  return a

def jacobi(a, n):
  if a == 0: return 1 if n == 1 else 0
  elif a == -1: return 1 if n % 2 == 0 else -1
  elif a == 1: return 1
  elif a == 2: 
    if n % 8 == 1 or n % 8 == 7: return 1
    elif n % 8 == 3 or n % 8 == 5: return -1
  elif a >= n: return jacobi(a % n, n)
  elif a % 2 == 0: return jacobi(2, n) * jacobi(a//2, n)
  else: return -1 * jacobi(n, a) if a % 4 == 3 and n % 4 == 3 else jacobi(n, a)

def findPrimRoot(p):
  if p == 2: return 1
  p1 = 2
  p2 = (p-1) // p1
  while(1):
    g = rnd(2, p-1)
    if not (pow(g, (p-1)//p1, p) == 1) and not pow(g, (p-1)//p2, p) == 1: return g


# Encode and Decode block for ElGamal
def encode(plain):
  z = []
  k = 32
  j = -1 * k
  for i in range(len(plain)):
    if i % k == 0:
      j += k
      z.append(0)
    z[j//k] += ord(plain[i])*(2**(8*(i%k)))
  return z

def decode(plain):
  bb = []
  k = 32
  for n in plain:
    for i in range(k):
      t = n
      for j in range(i+1, k): t = t % (2**(8*j))
      l = t // (2**(8*i))
      bb.append(l)
      n = n - (l*(2**(8*i)))
  dec = ''.join(chr(c) for c in bb)
  return dec


# Generate Public and Private key
def genKeys():
  p = findPrime()
  g = pow(findPrimRoot(p), 2, p)
  x = rnd(1, (p/2))
  y = pow(g, x, p)

  pubKey = PubKey(y, g, p)
  privKey = PrivKey(x, p)

  return pubKey, privKey


# Encrypt and Decrypt
def encrypt(key, plain):
  t1 = dt.now()
  e = encode(plain)
  cip = []
  for m in e:
    k = rnd(1, key.p - 2)
    a = pow(key.g, k, key.p)
    b = (pow(key.y, k, key.p) * m) % key.p
    cip.append([a, b])
  enc = ""
  for p in cip: enc += str(p[0]) + ' ' + str(p[1]) + ' '
  t2 = dt.now()
  return enc, (t2-t1).microseconds

def decrypt(key, cipher):
  t1 = dt.now()
  dec = []
  cip = cipher.split()
  for i in range(0, len(cip), 2):
    a = int(cip[i])
    b = int(cip[i+1])
    ax1 = pow(a, key.p-1-key.x, key.p)
    m = (b * ax1) % key.p
    dec.append(m)
  d = decode(dec)
  dec = "".join([p for p in d if p != '\x00'])
  t2 = dt.now()
  return dec, (t2-t1).microseconds
