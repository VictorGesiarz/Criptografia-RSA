# import time
# from sympy import randprime

# def generate_prime_with_time(a, b):
#     start_time = time.time()
#     prime = randprime(a, b)
#     end_time = time.time()
#     total_time = end_time - start_time
#     return prime, total_time

# a = 2**2047
# b = 2**2048 - 1
# primeP, generation_time = generate_prime_with_time(a, b)
# print(f"Prime P: {primeP}")
# print(f"Time taken: {generation_time} seconds")


import time
from sympy import randprime

def average_prime_generation_time(a, b, runs=10):
    total_time = 0
    for _ in range(runs):
        start_time = time.time()
        _ = randprime(a, b)  # Generate the prime but don't store it
        end_time = time.time()
        total_time += (end_time - start_time)
    
    average_time = total_time / runs
    return average_time

# Define a and b for 2048-bit range
a = 2**2047
b = 2**2048 - 1

# Calculate the average time over 10 runs
average_generation_time = average_prime_generation_time(a, b)
print(f"Average time taken to generate a 2048-bit prime: {average_generation_time} seconds")
