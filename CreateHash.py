import hashlib

def get_hash_algorithm(choice):
    """Returns the hash function based on user choice."""
    algorithms = {
        '1': 'md5',
        '2': 'sha1',
        '3': 'sha224',
        '4': 'sha256',
        '5': 'sha384',
        '6': 'sha512',
        '7': 'sha3_224',
        '8': 'sha3_256',
        '9': 'sha3_384',
        '10': 'sha3_512'
    }
    return algorithms.get(choice)

def hash_text(text, algorithm):
    """Hashes the given text using the specified algorithm."""
    hash_function = hashlib.new(algorithm)
    hash_function.update(text.encode())
    return hash_function.hexdigest()

def main():
    print("Choose a hashing algorithm from the following list:")
    print("1. MD5")
    print("2. SHA-1")
    print("3. SHA-224")
    print("4. SHA-256")
    print("5. SHA-384")
    print("6. SHA-512")
    print("7. SHA3-224")
    print("8. SHA3-256")
    print("9. SHA3-384")
    print("10. SHA3-512")

    choice = input("Enter the number of the algorithm you want to use: ")

    # Get the corresponding algorithm name
    algorithm = get_hash_algorithm(choice)
    
    if not algorithm:
        print("Invalid choice. Please run the script again and select a valid option.")
        return

    # Prompt the user to enter the text to hash
    text = input("Enter the text you want to hash: ")

    # Hash the text using the selected algorithm
    ciphertext = hash_text(text, algorithm)
    
    # Output the result
    print(f"Algorithm selected: {algorithm.upper()}")
    print(f"Hashed result: {ciphertext}")

if __name__ == "__main__":
    main()
