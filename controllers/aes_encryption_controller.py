from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from base64 import b64encode, b64decode
from binascii import Error as Base64Error
from os.path import getsize as file_size
from re import sub as re_sub
import settings
import logging


class AESEncryptionController:

    def __init__(self, mode='CBC', size=256):
        self._modes = {'CBC': AES.MODE_CBC, 'CFB': AES.MODE_CFB}
        self._sizes = (128, 192, 256)
        self._salt_len = 16
        self._iv_len = 16
        self._mac_len = 32
        self._mac_key_len = 32

        if mode.upper() not in self._modes:
            raise ValueError(mode + ' is not supported!')
        if size not in self._sizes:
            raise ValueError('Invalid key size!')
        self._mode = mode.upper()
        self._key_len = int(size / 8)
        self._master_key = None

        self.key_iterations = 20000
        self.base64 = True

    def encrypt(self, data, password=None):
        try:
            data = self._to_bytes(data)
            if self._mode == 'CBC':
                data = pad(data, AES.block_size)

            salt = self._random_bytes(self._salt_len)
            iv = self._random_bytes(self._iv_len)

            aes_key, mac_key = self._keys(salt, password)
            cipher = self._cipher(aes_key, iv)
            ciphertext = cipher.encrypt(data)
            mac = self._sign(iv + ciphertext, mac_key)

            encrypted = salt + iv + ciphertext + mac
            if self.base64:
                encrypted = b64encode(encrypted)
            return encrypted
        except (TypeError, ValueError) as e:
            self._error_handler(e)

    def decrypt(self, data, password=None):
        try:
            data = self._to_bytes(data)
            data = b64decode(data) if self.base64 else data

            salt = data[:self._salt_len]
            iv = data[self._salt_len: self._salt_len + self._iv_len]
            ciphertext = data[self._salt_len + self._iv_len: -self._mac_len]
            mac = data[-self._mac_len:]

            aes_key, mac_key = self._keys(salt, password)
            self._verify(iv + ciphertext, mac, mac_key)

            cipher = self._cipher(aes_key, iv)
            plaintext = cipher.decrypt(ciphertext)
            if self._mode == 'CBC':
                plaintext = unpad(plaintext, AES.block_size)
            return plaintext
        except (TypeError, ValueError, Base64Error) as e:
            self._error_handler(e)

    def encrypt_file(self, path, password=None):
        try:
            salt = self._random_bytes(self._salt_len)
            iv = self._random_bytes(self._iv_len)

            aes_key, mac_key = self._keys(salt, password)
            cipher = self._cipher(aes_key, iv)
            hmac = HMAC.new(mac_key, digestmod=SHA256)
            new_path = path + f'.{settings.EXTENSION_AES_ENCRYPTION}'

            with open(new_path, 'wb') as f:
                f.write(salt + iv)
                hmac.update(iv)

                for chunk, is_last in self._file_chunks(path):
                    if self._mode == 'CBC' and is_last:
                        chunk = pad(chunk, AES.block_size)
                    data = cipher.encrypt(chunk)
                    f.write(data)
                    hmac.update(data)

                f.write(hmac.digest())
            return new_path
        except (TypeError, ValueError, IOError) as e:
            self._error_handler(e)

    def decrypt_file(self, path, password=None):
        try:
            with open(path, 'rb') as f:
                salt = f.read(self._salt_len)
                iv = f.read(self._iv_len)
                f.seek(file_size(path) - self._mac_len)
                mac = f.read(self._mac_len)

            aes_key, mac_key = self._keys(salt, password)
            self._verify_file(path, mac, mac_key)
            cipher = self._cipher(aes_key, iv)
            new_path = re_sub(r'\.'+settings.EXTENSION_AES_ENCRYPTION+'$', '', path)

            with open(new_path, 'wb') as f:
                chunks = self._file_chunks(
                    path, self._salt_len + self._iv_len, self._mac_len
                )
                for chunk, is_last in chunks:
                    data = cipher.decrypt(chunk)

                    if self._mode == 'CBC' and is_last:
                        data = unpad(data, AES.block_size)
                    f.write(data)
            return new_path
        except (TypeError, ValueError, IOError) as e:
            self._error_handler(e)

    def set_master_key(self, key, raw=False):
        try:
            if not raw:
                key = b64decode(key)
            self._master_key = self._to_bytes(key)
        except (TypeError, Base64Error) as e:
            self._error_handler(e)

    def get_master_key(self, raw=False):
        if self._master_key is None:
            self._error_handler(ValueError('The key is not set!'))
        elif not raw:
            return b64encode(self._master_key)
        else:
            return self._master_key

    def random_key_gen(self, key_len=32, raw=False):
        self._master_key = self._random_bytes(key_len)
        if not raw:
            return b64encode(self._master_key)
        return self._master_key

    def _keys(self, salt, password):
        if password is not None:
            dkey = PBKDF2(
                password, salt, self._key_len + self._mac_key_len,
                self.key_iterations, hmac_hash_module=SHA512
            )
        elif self._master_key is not None:
            dkey = HKDF(
                self._master_key, self._key_len + self._mac_key_len,
                salt, SHA256
            )
        else:
            raise ValueError('No password or key specified!')
        return (dkey[:self._key_len], dkey[self._key_len:])

    def _random_bytes(self, size):
        return get_random_bytes(size)

    def _cipher(self, key, iv):
        return AES.new(key, self._modes[self._mode], IV=iv)

    def _sign(self, ciphertext, key):
        hmac = HMAC.new(key, ciphertext, digestmod=SHA256)
        return hmac.digest()

    def _sign_file(self, path, key):
        hmac = HMAC.new(key, digestmod=SHA256)
        for data, _ in self._file_chunks(path, self._salt_len):
            hmac.update(data)
        return hmac.digest()

    def _verify(self, data, mac, key):
        hmac = HMAC.new(key, data, digestmod=SHA256)
        hmac.verify(mac)

    def _verify_file(self, path, mac, key):
        hmac = HMAC.new(key, digestmod=SHA256)
        beg, end = self._salt_len, self._mac_len

        for chunk, _ in self._file_chunks(path, beg, end):
            hmac.update(chunk)
        hmac.verify(mac)

    def _error_handler(self, exception):
        logging.error(exception)

    def _file_chunks(self, path, beg=0, end=0):
        size = 1024
        end = file_size(path) - end

        with open(path, 'rb') as f:
            pos = (len(f.read(beg)))
            while pos < end:
                size = size if end - pos > size else end - pos
                data = f.read(size)
                pos += len(data)

                yield (data, pos == end)

    def _to_bytes(self, data, encoding='utf-8'):
        if hasattr(data, 'encode'):
            data = bytes(data, encoding)
        if type(data) is bytearray:
            data = bytes(data)
        return data