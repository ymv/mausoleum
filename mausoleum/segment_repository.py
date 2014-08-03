from hashlib import md5
from uuid import uuid4
from os.path import join
import logging
from mausoleum.stat import Timer
from mausoleum.slab import SlabFile

def random_string(l):
    with open('/dev/urandom') as f:
        return f.read(l)

class SegmentRepository(object):
    def __init__(self, connection, salt, pk, stage, use_cache=True, max_size=None):
        self._con = connection
        self._stage = stage
        self._salt = salt
        self._slab = None
        self._slab_name = None
        self._block_size = 2**20
        self._pk = pk
        self._logger = logging.getLogger('SegmentRepository')
        self._logger.info('Salt: %s, pk: %s, stage: %s', salt, pk, stage)
        self._timer = Timer.getTimer('SegmentRepository')
        self._use_cache = use_cache
        self._max_size = max_size
        if self._use_cache:
            c = self._con.cursor()
            c.execute('SELECT hash FROM slab_segment')
            self._cache = set(x for x, in c)

    def open_slab(self):
        self._timer.start('open_slab')
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

        self._slab = SlabFile(open(join(self._stage, name), 'a'), self._pk)
        self._slab_name = name
        self._timer.end('open_slab')

    def close_slab(self, final=False):
        self._timer.start('close_slab')
        self._logger.info('Closing%s slab: %s', ' and locking' if final else '', self._slab_name)
        self._slab.close()

        c = self._con.cursor()
        c.execute('UPDATE slab SET state = %s WHERE name = %s', ('closed' if final else 'open', self._slab_name))
        self._con.commit()

        self._slab = None
        self._slab_name = None
        self._timer.end('close_slab')

    def write_segment(self, hash, data):
        self._timer.start('write_segment')
        digest = hash.hexdigest()
        offset = self._slab.tell()

        self._logger.debug('Writing segment data %s, %d bytes @ %d', digest, len(data), offset)
        self._timer.start('write_segment/slab')
        self._slab.write(hash, data)
        self._timer.end('write_segment/slab')

        c = self._con.cursor()
        c.execute('INSERT INTO slab_segment (slab, offset, hash) VALUES (%s, %s, %s)', (self._slab_name, offset, digest))
        self._con.commit()
        if self._use_cache:
            self._cache.add(digest)
        if self._max_size and self._slab.tell() > self._max_size:
            self.close_slab(True)
            self.open_slab()
        self._timer.end('write_segment')

    def segment_exists(self, hash):
        self._timer.start('segment_exists')
        if self._use_cache:
            self._timer.end('segment_exists')
            return hash.hexdigest() in self._cache
        c = self._con.cursor()
        c.execute('SELECT 1 FROM slab_segment WHERE hash = %s LIMIT 1', (hash.hexdigest(),))
        self._timer.end('segment_exists')
        return c.fetchone() is not None

    def process_file(self, file_name):
        segments = []
        self._logger.debug('Processing file: %s', file_name)
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
                    self._logger.debug('New segment: %s', digest)
                    self.write_segment(h, b)
                else:
                    self._logger.debug('Existing segment: %s', digest)
        return segments
