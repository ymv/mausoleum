from hashlib import md5
from struct import pack
from uuid import uuid4
from os.path import join
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import logging

def random_string(l):
    with open('/dev/urandom') as f:
        return f.read(l)

class SegmentRepository(object):
    def __init__(self, connection, salt, pk, stage):
        self._con = connection
        self._stage = stage
        self._salt = salt
        self._slab = None
        self._slab_name = None
        self._block_size = 2**20
        self._pk = pk
        self._logger = logging.getLogger('SegmentRepository')
        self._logger.info('Salt: %s, pk: %s, stage: %s', salt, pk, stage)

    def open_slab(self):
        c = self._con.cursor()
        c.execute('SELECT name FROM slab WHERE state = %s LIMIT 1 FOR UPDATE', ('open',))
        name, = c.fetchone() or (None,)
        if name:
            self._logger.info('Opening slab: %s', name)
            c.execute('UPDATE slab SET state = %s WHERE name = %s', ('busy', name))
        else:
            name = str(uuid4())
            self._logger.info('Creating new slab: %s', name)
            c.execute('INSERT INTO slab (name, state) VALUES (%s, %s)', (name, 'busy'))
        self._con.commit()

        self._slab = open(join(self._stage, name), 'a')
        self._slab_name = name

    def close_slab(self):
        self._logger.info('Closing slab: %s', self._slab_name)
        self._slab.close()

        c = self._con.cursor()
        c.execute('UPDATE slab SET state = %s WHERE name = %s', ('open', self._slab_name))
        self._con.commit()

        self._slab = None
        self._slab_name = None

    def write_encrypted_segment(self, hash, payload):
        key = random_string(16)
        iv = random_string(16)
        encrypted_key = PKCS1_OAEP.new(self._pk).encrypt(key+iv)

        pad = 16 - len(payload) % 16 
        data = payload + chr(pad)*pad
        encrypted_payload = AES.new(key, mode=AES.MODE_CBC, IV=iv).encrypt(data)
        header = pack('!b16sL', 1, hash.digest(), len(encrypted_key))
        self._logger.info('Writing header|meta|key|ciphertext: 5|%d|%d|%d', len(header), len(encrypted_key), len(encrypted_payload))
        self._slab.write(pack('!bL', 1, len(encrypted_payload)+len(encrypted_key)+len(header)))
        self._slab.write(header)
        self._slab.write(encrypted_key)
        self._slab.write(encrypted_payload)

    def write_segment(self, hash, data):
        offset = self._slab.tell()
        self._logger.info('Writing segment data %s, %d bytes @ %d', hash.hexdigest(), len(data), offset)
        self.write_encrypted_segment(hash, data)
        self._slab.flush()

        c = self._con.cursor()
        c.execute('INSERT INTO slab_segment (slab, offset, hash) VALUES (%s, %s, %s)', (self._slab_name, offset, hash.hexdigest()))
        self._con.commit()

    def segment_exists(self, hash):
        c = self._con.cursor()
        c.execute('SELECT 1 FROM slab_segment WHERE hash = %s LIMIT 1', (hash.hexdigest(),))
        return c.fetchone() is not None

    def process_file(self, file_name):
        segments = []
        self._logger.info('Processing file: %s', file_name)
        with open(file_name) as f:
            while True:
                b = f.read(self._block_size)
                if not b:
                    break
                h = md5()
                h.update(self._salt)
                h.update(b)
                digest = h.hexdigest()
                segments.append(digest)
                if not self.segment_exists(h):
                    self._logger.info('New segment: %s', digest)
                    self.write_segment(h, b)
                else:
                    self._logger.info('Existing segment: %s', digest)
        return segments
