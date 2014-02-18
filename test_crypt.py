#!/bin/env python

import bcrypt
import string

password = "super secret password"

hashed = bcrypt.hashpw(password, bcrypt.gensalt(12))
print hashed

hashed2 = bcrypt.hashpw(password, bcrypt.gensalt(12))
print hashed2

check = bcrypt.hashpw(password, hashed)
print check
if bcrypt.hashpw(password, hashed2) == hashed2:
  print "It matheds!"
else:
  print "It doesn't math"

hashed2_str = str(hashed2)
print hashed2_str
if bcrypt.hashpw(password, hashed2_str) == hashed2_str:
  print "It matheds!"
else:
  print "It doesn't math"

hashed2_str = str(hashed2)
print hashed2_str
hashed2_str = '%sM%s' %(hashed2_str[0:10], hashed2_str[11:])
print hashed2_str
if bcrypt.hashpw(password, hashed2_str) == hashed2_str:
  print "It matheds!"
else:
  print "It doesn't math"
