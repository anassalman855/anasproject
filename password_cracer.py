import hashlib

# Dictionary to store usernames and their corresponding hashes
user_hash_dict = {}

# Reading common passwords from the file
with open(r'D:\anas\syber\project\password cracer\common_passwords.txt', 'r') as f:
    common_passwords = f.read().splitlines()

# Reading username and hash pairs from the file
with open(r'D:\anas\syber\project\password cracer\username_hashes.txt', 'r') as f:
    text = f.read().splitlines()

    for user_hash in text:
        username, hash_value = user_hash.split(":")
        user_hash_dict[username] = hash_value

# Checking common passwords against stored hashes
for password in common_passwords:
    hashed_password = hashlib.md5(password.encode('utf-8')).hexdigest()

    for username, hash_value in user_hash_dict.items():
        if hashed_password == hash_value:
            print(f'HASH FOUND\n {username}:{password}')
