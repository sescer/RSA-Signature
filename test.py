import binascii
import random
import string
import unittest
from rsa import RSA
from rsa_signature import RSASignature


class RSASignatureTest(unittest.TestCase):
    """Class represents unit test for RSA digital signature."""

    @staticmethod
    def create_file_with_random_letters(filename, size):
        """
        Function for creating file with given size
        :param filename: filename of file, where will be written random letters
        :param size: size of file in bytes
        """
        chars = ''.join([random.choice(string.ascii_letters) for _ in range(size)])
        with open(filename, 'w') as file:
            file.write(chars)

    def test_small(self):
        """ Small test with simple string for checking of RSA DS """
        p = 11
        q = 17

        message = b"hello world"

        rsa = RSA(p, q)

        signature = RSASignature(message, rsa)
        cipher = signature.encrypt_message()
        self.assertTrue(signature.decrypt_message(cipher))

    def test_big(self):
        """ Big test with 2MB file of random letters for checking of RSA DS """
        p = 2387233477
        q = 1787233379

        input_filename = "big_test.txt"
        self.create_file_with_random_letters(input_filename, 2 * 1024 * 1024)
        with open(input_filename, "rb") as file:
            message = file.read()
        message = binascii.b2a_hex(message)

        rsa = RSA(p, q)

        signature = RSASignature(message, rsa)
        cipher = signature.encrypt_message()
        self.assertTrue(signature.decrypt_message(cipher))


if __name__ == "__main__":
    unittest.main()
