from time import time
import logging

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

    def deleted_files(self):
        c = self._con.cursor()
        c.execute('SELECT path, seen FROM file WHERE domain=%s AND state=%s', (self._domain, 'deleted',))
        return {path: (timestamp, 0) for path, timestamp in c}

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
