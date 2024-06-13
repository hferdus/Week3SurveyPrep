# hundredClients_tenQuestions.py
# 100 clients for 10 total survey questions
#program allows number of clients and questions to be manually altered, as well as number of choices in generate_random_answers function below
# might try to alter this such that user can input number of choices, clients, etc

import random
from openfhe import *

# generate random answers
def generate_random_answers(num_questions, num_clients):
    answer_choice = [0, 1, 2]
    answers = []
    for _ in range(num_questions):
        question_answers = []
        for _ in range(num_clients):
            question_answers.append(random.choice(answer_choice))
        answers.append(question_answers)
    return answers

# encrypt a list of answers
def encrypt_answers(crypto_context, public_key, answers):
    plaintext = crypto_context.MakePackedPlaintext(answers)
    ciphertext = crypto_context.Encrypt(public_key, plaintext)
    return ciphertext

# decrypt a ciphertext
def decrypt_answers(crypto_context, secret_key, ciphertext):
    plaintext = crypto_context.Decrypt(secret_key, ciphertext)
    return plaintext.GetPackedValue()

# perform homomorphic addition
def homomorphic_add(crypto_context, ciphertext1, ciphertext2):
    return crypto_context.EvalAdd(ciphertext1, ciphertext2)

# crypto context setup
parameters = CCParamsBFVRNS()
parameters.SetPlaintextModulus(65537)
parameters.SetMultiplicativeDepth(2)

crypto_context = GenCryptoContext(parameters)
crypto_context.Enable(PKESchemeFeature.PKE)
crypto_context.Enable(PKESchemeFeature.KEYSWITCH)
crypto_context.Enable(PKESchemeFeature.LEVELEDSHE)

# public private Key generation
key_pair = crypto_context.KeyGen()

# 10 questions for 100  == clients
num_questions = 10
num_clients = 100

random_answers = generate_random_answers(num_questions, num_clients)
print(f"Original random answers: {random_answers}")

# encrypt answers
ciphertexts = []
for answers in random_answers:  
    ciphertexts.append(encrypt_answers(crypto_context, key_pair.publicKey, answers))

# homomorphic addition of pairs of ciphertexts
ciphertext_additions = []
for i in range(0, num_questions, 2):
    ciphertext_additions.append(homomorphic_add(crypto_context, ciphertexts[i], ciphertexts[i+1]))

# decrypt original and added ciphertexts
decrypted_answers = []
for cipher in ciphertexts:
    decrypted_answers.append(decrypt_answers(crypto_context, key_pair.secretKey, cipher))

decrypted_additions = []
for cipher_add in ciphertext_additions:
    decrypted_additions.append(decrypt_answers(crypto_context, key_pair.secretKey, cipher_add))

# fix to make sure decryption is accurate length
decryptedAnswersList = [ans[:num_clients] for ans in decrypted_answers]
decryptedAdditionList = [ans[:num_clients] for ans in decrypted_additions]

print(f"Decrypted answers: {decryptedAnswersList}")
print(f"Decrypted additions: {decryptedAdditionList}")
