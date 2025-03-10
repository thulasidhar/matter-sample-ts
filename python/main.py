import base64

from python.SetupPayload import SetupPayload
from python.spake2p import generate_verifier

if __name__ == '__main__':
    salt = b'sample_salt_bytes'
    iteration = 1122 # SetupPayload.generate_iteration()
    passcode = 11223344 # SetupPayload.generate_passcode()
    discriminator = 3840 # SetupPayload.generate_descriminator() : 0 to 4095
    print("Salt: {}".format(salt))
    print("Random Iteration: {}".format(iteration))
    print("Random Passcode: {0:08d}".format(passcode))
    print("Random Discriminator: {}".format(discriminator))

    verifier = generate_verifier(passcode, salt, iteration)
    print(base64.b64encode(verifier).decode('ascii'))

    payload = SetupPayload(discriminator, passcode, 4, 1, 12340, 56780)
    print("Manualcode : {}".format(payload.generate_manualcode()))
