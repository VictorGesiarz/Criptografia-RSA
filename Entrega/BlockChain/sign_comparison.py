import random 
import json 
import time
from main import rsa_key
import matplotlib.pyplot as plt


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


def test():
	KEY_LENGTHS = [512, 1024, 2048, 4096]

	KEYS = {}
	for key_length in KEY_LENGTHS: 
		print("Generateing 5 randoms keys of length:", key_length)
		KEYS[key_length] = [rsa_key(bits_modulo=key_length) for _ in range(5)]

	messages = generate_random_messages()
	times = {}
	i = 0
	for key_length in KEY_LENGTHS: 
		times[key_length] = {'slow': [], 'fast': []}
		slow_times = []
		fast_times = []
		for message in messages:
			print(key_length, i)
			i += 1

			private_key = random.choice(KEYS[key_length])
			start = time.time()
			private_key.sign_slow(message)
			end = time.time()
			slow_times.append(end - start)

			start = time.time()
			private_key.sign(message)
			end = time.time()
			fast_times.append(end - start)

		times[key_length]['slow'] = slow_times
		times[key_length]['fast'] = fast_times

	with open('./BlockChain/Exercices/test_results.json', 'w') as file: 
		json.dump(times, file)


def print_mean_times():
	with open('./BlockChain/Exercices/test_results.json', 'r') as file: 
		times = json.load(file)
	
	columns = ["Type"] + list(times.keys())
	row1 = ["Slow"]
	row2 = ["Fast"]
	for key_length in times.keys(): 
		slow = times[key_length]['slow']
		average = sum(slow) / len(slow)
		row1.append(round(average, 4))
		fast = times[key_length]['fast']
		average = sum(fast) / len(fast)
		row2.append(round(average, 4))

	fig, ax = plt.subplots(figsize=(8, 4))
	ax.axis('off')
	table = ax.table(cellText=[row1, row2], colLabels=columns, loc='center', cellLoc='center')
	plt.show()


# test()
print_mean_times()