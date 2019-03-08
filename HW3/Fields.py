#!/usr/bin/env python3


# function to check if a number smaller than 50 is prime
def is_prime(n: int) -> bool:
	
	# generate a set of all non prime numbers <= 50
	non_prime = set()
	for num1 in range(2, 51):
		for num2 in range(num1, 51):
			val = num1 * num2
			if val <= 50: non_prime.add(val)
			
	# check if the given integer is in the set, if not, it's prime
	return n not in non_prime


# main block
if __name__ == "__main__":
	# get input from user
	n = int(input("Type an integer < 50 to test if Zn is a field or a ring: "))

	is_field = is_prime(n)

	# if n is prime, Zn is a field, otherwise it is a ring
	if is_field:
		print('field')
	else:
		print('ring')
