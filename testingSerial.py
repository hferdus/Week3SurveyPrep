import random
from openfhe import *
import tempfile
import os

# Set up the temporary directory for storing serialized files
datafolder = "demoData"

def generate_random_answers(num_questions, num_clients):
    answer_choice = [0, 1, 2]
    answers = []
    for _ in range(num_questions):
        question_answers = []
        for _ in range(num_clients):
            question_answers.append(random.choice(answer_choice))
        answers.append(question_answers)
    return answers

def encrypt_answers(crypto_context, public_key, answers):
    plaintext = crypto_context.MakePackedPlaintext(answers)
    ciphertext = crypto_context.Encrypt(public_key, plaintext)
    return ciphertext

def decrypt_answers(crypto_context, secret_key, ciphertext):
    plaintext = crypto_context.Decrypt(secret_key, ciphertext)
    return plaintext.GetPackedValue()

def homomorphic_add(crypto_context, ciphertext1, ciphertext2):
    return crypto_context.EvalAdd(ciphertext1, ciphertext2)

# Main action to perform encryption, serialization, deserialization, and homomorphic operations
def main_action():
    serType = BINARY  # or JSON
    print("This program requires the subdirectory `" + datafolder + "' to exist, otherwise you will get an error writing serializations.")

    parameters = CCParamsBFVRNS()
    parameters.SetPlaintextModulus(65537)
    parameters.SetMultiplicativeDepth(2)

    cryptoContext = GenCryptoContext(parameters)
    cryptoContext.Enable(PKESchemeFeature.PKE)
    cryptoContext.Enable(PKESchemeFeature.KEYSWITCH)
    cryptoContext.Enable(PKESchemeFeature.LEVELEDSHE)

    key_pair = cryptoContext.KeyGen()

    num_questions = 10
    num_clients = 100

    random_answers = generate_random_answers(num_questions, num_clients)
    print(f"Original random answers: {random_answers}")

    ciphertexts = []
    for i, answers in enumerate(random_answers):
        ciphertext = encrypt_answers(cryptoContext, key_pair.publicKey, answers)
        if not SerializeToFile(datafolder + f"/ciphertext_{i}.txt", ciphertext, serType):
            raise Exception(f"Error writing serialization of ciphertext_{i}.txt")
        ciphertexts.append(ciphertext)

    deserialized_ciphertexts = []
    for i in range(num_questions):
        ct, res = DeserializeCiphertext(datafolder + f"/ciphertext_{i}.txt", serType)
        if not res:
            raise Exception(f"Could not read the ciphertext_{i}.txt")
        deserialized_ciphertexts.append(ct)

    ciphertext_additions = []
    for i in range(0, num_questions, 2):
        ciphertext_add = homomorphic_add(cryptoContext, deserialized_ciphertexts[i], deserialized_ciphertexts[i+1])
        if not SerializeToFile(datafolder + f"/ciphertext_add_{i//2}.txt", ciphertext_add, serType):
            raise Exception(f"Error writing serialization of ciphertext_add_{i//2}.txt")
        ciphertext_additions.append(ciphertext_add)

    deserialized_additions = []
    for i in range(len(ciphertext_additions)):
        ct_add, res = DeserializeCiphertext(datafolder + f"/ciphertext_add_{i}.txt", serType)
        if not res:
            raise Exception(f"Could not read the ciphertext_add_{i}.txt")
        deserialized_additions.append(ct_add)

    decrypted_answers = []
    for cipher in deserialized_ciphertexts:
        decrypted_answers.append(decrypt_answers(cryptoContext, key_pair.secretKey, cipher))

    decrypted_additions = []
    for cipher_add in deserialized_additions:
        decrypted_additions.append(decrypt_answers(cryptoContext, key_pair.secretKey, cipher_add))

    decryptedAnswersList = [ans[:num_clients] for ans in decrypted_answers]
    decryptedAdditionList = [ans[:num_clients] for ans in decrypted_additions]

    print(f"Decrypted answers: {decryptedAnswersList}")
    print(f"Decrypted additions: {decryptedAdditionList}")

def main():
    global datafolder
    with tempfile.TemporaryDirectory() as td:
        datafolder = td + "/" + datafolder
        os.mkdir(datafolder)
        main_action()

if __name__ == "__main__":
    main()
