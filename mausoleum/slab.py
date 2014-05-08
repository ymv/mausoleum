from struct import pack, unpack
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import zlib

def random_string(l):
    with open('/dev/urandom') as f:
        return f.read(l)

class SlabFile(object):
    def __init__(self, file, pk):
        self._file = file
        self._pk = pk

    def tell(self):
        return self._file.tell()

    def close(self):
        return self._file.close()

    def write(self, hash, payload, compress=True):
        key = random_string(16)
        iv = random_string(16)
        encrypted_key = PKCS1_OAEP.new(self._pk).encrypt(key+iv)
        
        format = 1
        if compress:
            payload_compressed = zlib.compress(payload)
            if len(payload) - len(payload_compressed) > 16:
                format = 2
                payload = payload_compressed
        pad = 16 - len(payload) % 16 
        data = payload + chr(pad)*pad
        encrypted_payload = AES.new(key, mode=AES.MODE_CBC, IV=iv).encrypt(data)
        header = pack('!b16sL', format, hash.digest(), len(encrypted_key))
        self._file.write(pack('!bL', 1, len(encrypted_payload)+len(encrypted_key)+len(header)))
        self._file.write(header)
        self._file.write(encrypted_key)
        self._file.write(encrypted_payload)
        self._file.flush()

    def read(self):
        chunk_header = self._file.read(5)
        if not chunk_header:
            return None
        chunk_type, chunk_length = unpack('!bL', chunk_header)
        if chunk_type != 1:
            raise Exceptin('Bad chunk type: %s' % chunk_type)

        segment_header = self._file.read(21)
        segment_encoding, hash, key_size = unpack('!b16sL', segment_header)

        if segment_encoding != 1 and segment_encoding != 2:
            raise Exceptin('Bad segment encoding: %s' % segment_encoding)

        encrypted_key_iv = self._file.read(key_size)
        key_iv = PKCS1_OAEP.new(self._pk).decrypt(encrypted_key_iv)
        key, iv = key_iv[:16], key_iv[16:]

        encrypted_payload = self._file.read(chunk_length - key_size - 21)
        padded = AES.new(key, mode=AES.MODE_CBC, IV=iv).decrypt(encrypted_payload)
        payload = padded[:-ord(padded[-1])]

        if segment_encoding == 2:
            payload = zlib.decompress(payload)

        return hash, payload, segment_encoding

