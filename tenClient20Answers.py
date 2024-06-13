import random
from openfhe import *

# Generating the 10 client answers -- > vector
def generating_random_answers(questions, num_answers):
    answer_choice = [0, 1, 2]
    answer = []
    for i in range(num_answers):
        answer.append(random.choice(answer_choice))
    return answer

question1 = "Do you like Notre Dame?"
question2 = "Do you like Indiana?"
num_answers = 10

random_answers1 = generating_random_answers(question1, num_answers)
random_answers2 = generating_random_answers(question1, num_answers)


print(f"The first vector of generated answers is: {random_answers1}")
print(f"The second vector of generated answers is: {random_answers2}")

# OpenFHE section

parameters = CCParamsBFVRNS()
parameters.SetPlaintextModulus(65537)
parameters.SetMultiplicativeDepth(2)

crypto_context = GenCryptoContext(parameters)
crypto_context.Enable(PKESchemeFeature.PKE)
crypto_context.Enable(PKESchemeFeature.KEYSWITCH)
crypto_context.Enable(PKESchemeFeature.LEVELEDSHE)

# Public Private Key gen
key_pair = crypto_context.KeyGen()

# Random Answers List 1 ENCRYPT
plaintext1 = crypto_context.MakePackedPlaintext(random_answers1)
ciphertext1 = crypto_context.Encrypt(key_pair.publicKey, plaintext1)

# Random Answers List 2 ENCRYPT
plaintext2 = crypto_context.MakePackedPlaintext(random_answers2)
ciphertext2 = crypto_context.Encrypt(key_pair.publicKey, plaintext2)
 
# Ciphertext addition
ciphertext_adding_12 = crypto_context.EvalAdd(ciphertext1, ciphertext2)

#Decrypt List 1
decryptedList1 = crypto_context.Decrypt(key_pair.secretKey, ciphertext1)

#Decrypt List 2
decryptedList2 = crypto_context.Decrypt(key_pair.secretKey, ciphertext2)

#Decrypted Added List
decryptedAdditionList = crypto_context.Decrypt(key_pair.secretKey, ciphertext_adding_12)

print(f"First decrypted list: {decryptedList1}")
print(f"Second decrypted list: {decryptedList2}")
print(f"Homomorphic addition decrypted list: {decryptedAdditionList}")