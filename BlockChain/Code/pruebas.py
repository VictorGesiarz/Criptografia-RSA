import time
from main import rsa_key, rsa_public_key, transaction, block, block_chain

private_key = rsa_key(bits_modulo=2048)
print(private_key)
print()

print(" - - - - - - - - - - - - - - - - - - - - - - - - - - - - SIGN - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n")

message = 123456789
print("Message:", message, "\n")
signature_slow = private_key.sign_slow(message)
print("Signature (slow):", signature_slow, "\n")
signature_fast = private_key.sign(message)
print("Signature (fast):", signature_fast, "\n")
if signature_fast == signature_slow:
	print("Both methods give the same signature. \n\n")
	

print(" - - - - - - - - - - - - - - - - - - - - - - - - - - - - VERIFY - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n")

e, n = private_key.get_public_numbers()
public_key = rsa_public_key(e, n)

isExpectedMessage = public_key.verify(message, signature_fast)
if isExpectedMessage:
	print('The signature is correct.\n\n')
else: 
	print('The signature does not correspond to that message.\n\n')
	

print(" - - - - - - - - - - - - - - - - - - - - - - - - - - - - TRANSACTION - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n")

t1 = transaction(message, private_key)
print(t1)

isValid = t1.verify()
if isValid:
	print('The transaction is valid.\n\n')
else: 
	print('The transaction is not valid.\n\n')
	

print(" - - - - - - - - - - - - - - - - - - - - - - - - - - - - BLOCK - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n")

b1 = block()
b1.genesis(t1)

message = 987654321
t2 = transaction(message, private_key)
b2 = b1.next_block(t2)

print("\nBLOCK 1:\n- - - - - - - - - - - - - - - - - - - - \n", b1, "- - - - - - - - - - - - - - - - - - - - -\n")
print("\nBLOCK 2:\n- - - - - - - - - - - - - - - - - - - - \n", b2, "- - - - - - - - - - - - - - - - - - - - -\n")


print(" - - - - - - - - - - - - - - - - - - - - - - - - - - - - BLOCK CHAIN - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n")

chain = block_chain(t1)
chain.add_block(t2)
print(chain)

validChain, index = chain.verify()
if validChain:
	print("The Block Chain is valid, and all the blocks are correctly verified.\n\n")
else:
	print(f"The Block Chain is not valid, verification error at: {index}\n\n")


print(" - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n")