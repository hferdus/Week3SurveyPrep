import random
from openfhe import *

# Generating the 10 client answers -- > vector
def generating_random_answers(questions, num_answers):
    answer_choice = [0, 1]
    answer = []
    for i in range(num_answers):
        answer.append(random.choice(answer_choice))
    return answer

question = "Do you like Notre Dame?"
num_answers = 10

random_answers = generating_random_answers(question, num_answers)

print(f"The vector of generated answers is: {random_answers}")

# OpenFHE section

parameters = CCParamsBFVRNS()
parameters.SetPlaintextModulus(65537)
parameters.SetMultiplicativeDepth(2)

crypto_context = GenCryptoContext(parameters)
crypto_context.Enable(PKESchemeFeature.PKE)
crypto_context.Enable(PKESchemeFeature.KEYSWITCH)
crypto_context.Enable(PKESchemeFeature.LEVELEDSHE)

key_pair = crypto_context.KeyGen()

plaintext1 = crypto_context.MakePackedPlaintext(random_answers)
ciphertext1 = crypto_context.Encrypt(key_pair.publicKey, plaintext1)

def values():
    x,y = key_pair.secretKey.ciphertext1
    return x, y

