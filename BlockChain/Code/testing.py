import json

from main import block_chain


def load_file(file):
	with open(file, 'r') as chain_str:
		file_content = chain_str.read()
		file_content = file_content.replace('"', '')
		file_content = file_content.replace("'", '"')

	data_dict = json.loads(file_content)
	return data_dict

def test(file):
	chain_dict = load_file(file)

	chain = block_chain()
	chain.from_dictionary(chain_dict)
	print(chain)

	validChain, index = chain.verify()
	if validChain:
		print("The Block Chain is valid, and all the blocks are correctly verified.\n\n")
	else:
		print(f"The Block Chain is not valid, verification error at: {index}\n\n")


path = './BlockChain/'

valid = 'Cadena_bloques_valida.block'
false_block = 'Cadena_bloques_bloque_falso.block'
false_seed = 'Cadena_bloques_seed_falsa.block'
false_transaction = 'Cadena_bloques_transaccion_falsa.block'

test(path + false_block)
test(path + false_seed)
test(path + false_transaction)
test(path + valid)