from argparse import ArgumentParser
from os import stat, walk
from os.path import join, relpath
import json
import logging
from magic import Magic
from MySQLdb import connect
from Crypto.PublicKey import RSA
from mausoleum.repository import Repository
from mausoleum.segment_repository import SegmentRepository

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
    logging.basicConfig(level=logging.INFO)
    parser = ArgumentParser(description='Mausoleum archival tool')
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
    main()
