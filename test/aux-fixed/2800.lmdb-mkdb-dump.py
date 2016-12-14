#!/usr/bin/env python
import os
import lmdb

if os.path.exists('2800.mdb'):
    os.unlink('2800.mdb')

env = lmdb.open('2800.mdb', subdir=False);
with env.begin(write=True) as txn:
   txn.put('first', 'data for first')
   txn.put('second', 'A=1 B=2')
   txn.put('third', 'A1:B2:C3')
   cursor = txn.cursor()
   for key, value in cursor:
       print key, "=>", value
