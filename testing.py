import random
from openfhe import *

# Generate random answers
def generate_random_answers(num_questions, num_clients):
    answer_choice = [0, 1, 2]
    answers = []
    for _ in range(num_questions):
        question_answers = []
        for _ in range(num_clients):
            question_answers.append(random.choice(answer_choice))
        answers.append(question_answers)
    return answers

# Encrypt a list of answers
def encrypt_answers(crypto_context, public_key, answers):
    plaintext = crypto_context.MakePackedPlaintext(answers)
    ciphertext = crypto_context.Encrypt(public_key, plaintext)
    return ciphertext

# Decrypt a ciphertext
def decrypt_answers(crypto_context, secret_key, ciphertext):
    plaintext = crypto_context.Decrypt(secret_key, ciphertext)
    return plaintext.GetPackedValue()

# Perform homomorphic addition
def homomorphic_add(crypto_context, ciphertext1, ciphertext2):
    return crypto_context.EvalAdd(ciphertext1, ciphertext2)

# Serialize ciphertext to a file
def serialize_ciphertext(ciphertext, filename):
    with open(filename, 'w') as file:
        ciphertext.Serialize(file)

# Deserialize ciphertext from a file
def deserialize_ciphertext(crypto_context, filename):
    with open(filename, 'r') as file:
        ciphertext = crypto_context.DeserializeCiphertext(file)
    return ciphertext

# Crypto context setup
parameters = CCParamsBFVRNS()
parameters.SetPlaintextModulus(65537)
parameters.SetMultiplicativeDepth(2)

crypto_context = GenCryptoContext(parameters)
crypto_context.Enable(PKESchemeFeature.PKE)
crypto_context.Enable(PKESchemeFeature.KEYSWITCH)
crypto_context.Enable(PKESchemeFeature.LEVELEDSHE)

# Public-private key generation
key_pair = crypto_context.KeyGen()

# 10 questions for 100 clients
num_questions = 10
num_clients = 100

random_answers = generate_random_answers(num_questions, num_clients)
print(f"Original random answers: {random_answers}")

# Encrypt answers
ciphertexts = []
for i, answers in enumerate(random_answers):
    ciphertext = encrypt_answers(crypto_context, key_pair.publicKey, answers)
    serialize_ciphertext(ciphertext, f"ciphertext_{i}.txt")
    ciphertexts.append(ciphertext)

# Deserialize ciphertexts (for demonstration purposes)
deserialized_ciphertexts = []
for i in range(num_questions):
    deserialized_ciphertexts.append(deserialize_ciphertext(crypto_context, f"ciphertext_{i}.txt"))

# Homomorphic addition of pairs of ciphertexts
ciphertext_additions = []
for i in range(0, num_questions, 2):
    ciphertext_add = homomorphic_add(crypto_context, deserialized_ciphertexts[i], deserialized_ciphertexts[i+1])
    serialize_ciphertext(ciphertext_add, f"ciphertext_add_{i//2}.txt")
    ciphertext_additions.append(ciphertext_add)

# Deserialize additions (for demonstration purposes)
deserialized_additions = []
for i in range(len(ciphertext_additions)):
    deserialized_additions.append(deserialize_ciphertext(crypto_context, f"ciphertext_add_{i}.txt"))

# Decrypt original and added ciphertexts
decrypted_answers = []
for cipher in deserialized_ciphertexts:
    decrypted_answers.append(decrypt_answers(crypto_context, key_pair.secretKey, cipher))

decrypted_additions = []
for cipher_add in deserialized_additions:
    decrypted_additions.append(decrypt_answers(crypto_context, key_pair.secretKey, cipher_add))

# Fix to make sure decryption is accurate length
decryptedAnswersList = [ans[:num_clients] for ans in decrypted_answers]
decryptedAdditionList = [ans[:num_clients] for ans in decrypted_additions]

print(f"Decrypted answers: {decryptedAnswersList}")
print(f"Decrypted additions: {decryptedAdditionList}")
