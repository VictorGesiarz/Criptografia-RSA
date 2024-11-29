import random
import json
from main import rsa_key, rsa_public_key, transaction, block, block_chain


def generate_random_messages(n=100, digits=37):
	messages = []
	for i in range(n): 
		lower_bound = 10**(digits - 1)  
		upper_bound = 10**digits - 1  
		random_number = random.randint(lower_bound, upper_bound)
		while random_number in messages: 
			random_number = random.randint(lower_bound, upper_bound)
		messages.append(random_number)
	return messages


def generate_valid_chain():
	KEY_LENGTH = 2048
	messages = generate_random_messages()

	private_key = rsa_key(bits_modulo=KEY_LENGTH)	
	t = transaction(messages[0], private_key)
	chain = block_chain(t)
	for message in messages[1:]:
		private_key = rsa_key(bits_modulo=KEY_LENGTH)	
		t = transaction(message, private_key)
		chain.add_block(t)

	return chain 


def generate_invalid_chain():
	chain = generate_valid_chain()
	modified_block = chain.list_of_blocks[32] # Posicion 33, suponiendo que empieza en el 0 
	modified_block.seed = random.randint(0, int(1e9))  
	return chain


def print_result(chain):
	validChain, index = chain.verify()
	if validChain:
		print("The Block Chain is valid, and all the blocks are correctly verified.\n\n")
	else:
		print(f"The Block Chain is not valid, verification error at: {index}\n\n")


def save_chain(chain, file):
	with open(file, 'w') as f:
		f.write(json.dumps(repr(chain)))


chain1 = generate_valid_chain()
print_result(chain1)
save_chain(chain1, './BlockChain/Exercices/valid_chain.block')
chain2 = generate_invalid_chain()
print_result(chain2)
save_chain(chain2, './BlockChain/Exercices/invalid_chain.block')