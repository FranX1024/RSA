import base64, sys, rsa

def hextoint(s):
    return int(s, 16)

if sys.argv[1] == 'make-keys':
    name = sys.argv[2]
    print("Computing...")
    k2, k1 = rsa.create_keys()
    pubf = open(name + '.pub', 'w')
    privf = open(name + '.priv', 'w')
    pubf.write(hex(k1[0])[2:] + ':' + hex(k1[1])[2:])
    privf.write(hex(k2[0])[2:] + ':' + hex(k2[1])[2:])
    pubf.close()
    privf.close()
    print('Done!')
elif sys.argv[1] == 'encrypt':
    if sys.argv[3] != 'for':
        print('Error: specify for whom you are encrypting. (Which public key to use)')
        exit(1)
    if sys.argv[5] != 'to':
        print('Error: specify to which file you want the output saved.')
    pubf = open(sys.argv[4] + '.pub', 'r')
    msgf = open(sys.argv[2], 'rb')
    pubkey = tuple(map(hextoint, pubf.read().split(':')))
    msg = msgf.read()
    pubf.close()
    msgf.close()
    enc = rsa.encrypt_bytes(msg, pubkey)
    encf = open(sys.argv[6], 'wb')
    encf.write(base64.b64encode(enc))
    encf.close()
    print("Done!")
elif sys.argv[1] == 'decrypt':
    if sys.argv[3] != 'as':
        print('Error: specify which private key to use.')
        exit(1)
    if sys.argv[5] != 'to':
        print('Error: specify to which file you want the output saved.')
    privf = open(sys.argv[4] + '.priv', 'r')
    msgf = open(sys.argv[2], 'rb')
    privkey = tuple(map(hextoint, privf.read().split(':')))
    msg = base64.b64decode(msgf.read())
    privf.close()
    msgf.close()
    dec = rsa.decrypt_bytes(msg, privkey)
    decf = open(sys.argv[6], 'wb')
    decf.write(dec.strip(b'\x00'))
    decf.close()
    print("Done!")
else:
    print("Usage:")
    print("python test.py makekeys [name]")
    print("python test.py encrypt [infile] from [name] to [outfile]")
    print("python test.py decrypt [infile] as [name] to [outfile]")
