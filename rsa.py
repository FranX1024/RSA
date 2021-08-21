# cryptographically secure
# random library alternative
import secrets

def eucalg(a, b):
	# make a the bigger one and b the lesser one
	swapped = False
	if a < b:
		a, b = b, a
		swapped = True
	# ca and cb store current a and b in form of
	# coefficients with initial a and b
	# a' = ca[0] * a + ca[1] * b
	# b' = cb[0] * a + cb[1] * b
	ca = (1, 0)
	cb = (0, 1)
	while b != 0:
		# k denotes how many times number b
		# can be substracted from a
		k = a // b
		# swap a and b so b is always the lesser one
		a, b, ca, cb = b, a-b*k, cb, (ca[0]-k*cb[0], ca[1]-k*cb[1])
	if swapped:
		return (ca[1], ca[0])
	else:
		return ca

def modpow(b, e, n):
	# find length of e in bits
	tst = 1
	siz = 0
	while e >= tst:
		tst <<= 1
		siz += 1
	siz -= 1
	# calculate the result
	r = 1
	for i in range(siz, -1, -1):
		r = (r * r) % n
		if (e >> i) & 1: r = (r * b) % n
	return r

# f(a, b) = (b, a + b)
# Matrix of the linear function:
# [ 0 1 ]
# [ 1 1 ]

# matrix multiplication
def sqmatrixmul(m1, m2, w, mod):
	mr = [[0 for j in range(w)] for i in range(w)]
	for i in range(w):
		for j in range(w):
			for k in range(w):
				mr[i][j] = (mr[i][j] + m1[i][k] * m2[k][j]) % mod
	return mr

# fibonacci calculator
def fib(x, mod):
	if x < 3: return 1
	x -= 2
	# find length of e in bits
	tst = 1
	siz = 0
	while x >= tst:
		tst <<= 1
		siz += 1
	siz -= 1
	# calculate the matrix
	fm = [
		# function matrix
		[0, 1],
		[1, 1]
	]
	rm = [
		# result matrix
		# (identity)
		[1, 0],
		[0, 1]
	]
	for i in range(siz, -1, -1):
		rm = sqmatrixmul(rm, rm, 2, mod)
		if (x >> i) & 1:
			rm = sqmatrixmul(rm, fm, 2, mod)

	# second row of resulting vector is result
	return (rm[1][0] + rm[1][1]) % mod

def genprime(siz):
	while True:
		num = (1 << (siz - 1)) + secrets.randbits(siz - 1) - 10;
		# num must be 3 or 7 (mod 10)
		num -= num % 10
		num += 3 # 3 (mod 10)
		# heuristic test
		if modpow(2, num - 1, num) == 1 and fib(num + 1, num) == 0:
			return num
		num += 5 # 7 (mod 10)
		# heuristic test
		if modpow(2, num - 1, num) == 1 and fib(num + 1, num) == 0:
			return num

def create_keys():
	p = genprime(1024)
	q = genprime(1024)
	n = p * q
	lambda_n = (p - 1) * (q - 1)
	e = 35537
	d = eucalg(e, lambda_n)[0]
	if d < 0: d += lambda_n
	return (d, n), (e, n)

def encrypt_bytes(data, key):
	data = bytearray(data)
	cdata = bytearray()
	for i in range(0, len(data), 256):
		# read 256 bytes and store as long
		# to m
		m = 0
		for j in range(256):
			if i + j < len(data):
				m = (m << 8) + data[i + j]
			else:
				m <<= 8
		# encrypt m
		c = modpow(m, key[0], key[1])
		# store c into cdata
		for j in range(255, -1, -1):
			cdata.append((c >> (j * 8)) & 255)
	return bytes(cdata)

# both functions are essencially the same,
# the only difference is in which key you use
decrypt_bytes = encrypt_bytes
