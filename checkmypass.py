import requests
import hashlib
import sys



def request_api_data(query_char):
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	res = requests.get(url)
	
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again.')


	return res


#def read_res(response):
#	print(response.text)

def get_passwd_leaks_counts(hashes, hash_tocheck):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h,count in hashes:
		if h == hash_tocheck:
			return count

	return 0
	




def pwned_api_check(password):
	#print(password.encode('utf-8'))
	#print(hashlib.sha1(password.encode('utf-8')).hexdigest())
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first5_char, tail = sha1password[:5], sha1password[5:]
	response = request_api_data(first5_char)
	#print(first5_char,tail)
	#print(response)
	return get_passwd_leaks_counts(response, tail)



def main(args):
	for password in args:
		counts = pwned_api_check(password)
	if counts:
		print(f'{password} was found {counts} times... You should change it!')
	else:
		print(f'{password} was NOT found!   carry on!')
	return 'done!!!'


if __name__ == '__main__':
	sys.exit(main(sys.argv[1:]))



