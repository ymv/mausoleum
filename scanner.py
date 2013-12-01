from time import time
from hashlib import md5
from os import listdir, stat, walk
from os.path import join, isfile, relpath
from magic import Magic
import uuid
from struct import pack
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import logging

def random_string(l):
    with open('/dev/urandom') as f:
        return f.read(l)

class Repository(object):
    def __init__(self, connection, domain):
        self._con = connection
        self._logger = logging.getLogger('Repository.'+domain)
        self._domain = domain

    def active_files(self):
        '''
            () -> { unicode/file name/: (integer/timestamp/, integer/size/) }
        '''
        c = self._con.cursor()
        c.execute('SELECT path, updated, size FROM file WHERE domain=%s AND state=%s', (self._domain, 'active',))
        return {path: (timestamp, size) for path, timestamp, size in c}

    def mark_deleted(self, names):
        c = self._con.cursor()
        t = int(time())
        for name in names:
            self._logger.info('Deleted file: %s', name)
            c.execute('UPDATE file SET state = %s WHERE domain = %s AND path = %s AND state = %s', ('history', self._domain, name, 'active'))
            c.execute('INSERT INTO file (domain, path, seen, state) VALUES (%s, %s, %s, %s)', (self._domain, name, t, 'deleted'))

    def mark_seen(self, names):
        c = self._con.cursor()
        t = int(time())
        for name in names:
            self._logger.info('Seen file: %s', name)
            c.execute('UPDATE file SET seen = %s WHERE domain = %s AND path = %s AND state = %s', (t, self._domain, name, 'active'))

    def mark_updated(self, data):
        c = self._con.cursor()
        t = int(time())
        for name, (timestamp, size, mime, segments) in data.iteritems():
            self._logger.info('Updated file: %s [%s]', name, ','.join(segments))
            c.execute('UPDATE file SET state = %s WHERE domain = %s AND path = %s AND state = %s', ('history', self._domain, name, 'active'))
            c.execute('INSERT INTO file (domain, path, seen, updated, size, mime, state) VALUES (%s, %s, %s, %s, %s, %s, %s)', (self._domain, name, t, timestamp, size, mime, 'active'))
            file_id = c.lastrowid
            for i, hash in enumerate(segments):
                c.execute('INSERT INTO file_segment(file_id, i, hash) VALUES (%s, %s, %s)', (file_id, i, hash))

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
            name = str(uuid.uuid4())
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

def scan_directory(repo, slab_repo, directory):
    m = Magic(True)
    active = repo.active_files()
    updated = {}
    confirmed = set()
    slab_repo.open_slab()
    try:
        for dirpath, dirnames, filenames in walk(directory):
            rel_path = relpath(dirpath, directory) if directory != dirpath else ''
            for file_name in filenames:
                full_name = join(dirpath, file_name)
                file_name = join(rel_path, file_name)
                if not isfile(full_name):
                    continue
                stats = stat(full_name)
                confirmed.add(file_name)
                seen_ts, seen_size = active.get(file_name, (None, None))
                if seen_ts != long(stats.st_mtime) or seen_size != long(stats.st_size):
                    segments = slab_repo.process_file(full_name)
                    with open(full_name) as f:
                        mime = m.from_buffer(f.read(2**15))
                    updated[file_name] = long(stats.st_mtime), long(stats.st_size), mime, segments
    finally:
        slab_repo.close_slab()
    repo.mark_deleted(set(active) - confirmed)
    repo.mark_seen(confirmed - set(updated))
    repo.mark_updated(updated)

def main():
    import argparse
    import json
    from MySQLdb import connect
    parser = argparse.ArgumentParser(description='Mausoleum archival tool')
    parser.add_argument('--config', help='Config file', default='config.json')
    args = parser.parse_args()
    with open(args.config) as f:
        config = json.load(f)


    seg_repository_con = connect(db=config['database'], charset='utf8')
    with open(config['key']) as f:
        pk = RSA.importKey(f.read())
    seg_repository = SegmentRepository(seg_repository_con, config['salt'], pk, config['stage'])

    repository_con = connect(db=config['database'], charset='utf8')
    for domain, directory in config['directories'].iteritems():
        repository = Repository(repository_con, domain)
        scan_directory(repository, seg_repository, directory)
        repository_con.commit()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
