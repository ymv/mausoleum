from argparse import ArgumentParser
from os import stat, walk
from os.path import join, relpath
from sys import stderr, exit
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

def make_seg_repository(config):
    seg_repository_con = connect(db=config['database'], charset='utf8')
    with open(config['key']) as f:
        pk = RSA.importKey(f.read())
    return SegmentRepository(seg_repository_con, config['salt'], pk, config['stage'])

def operation_scan(config, _):
    seg_repository = make_seg_repository(config)

    repository_con = connect(db=config['database'], charset='utf8')
    for domain, directory in config['directories'].iteritems():
        repository = Repository(repository_con, domain)
        scan_directory(repository, seg_repository, directory)
        repository_con.commit()

def operation_ls(config, args):
    repository_con = connect(db=config['database'], charset='utf8')
    max_domain = max(map(len, config['directories']))
    for domain in config['directories']:
        repository = Repository(repository_con, domain)
        files = getattr(repository, 'deleted_files' if args.deleted else 'active_files')()
        max_len = max(map(len, files))
        for fn in sorted(files):
            ts, size = files[fn]
            print '%-*s %-*s %d %d' % (max_domain, domain, max_len, fn, ts or 0, size or 0)

def main():
    parser = ArgumentParser(description='Mausoleum archival tool')
    operations = {
        'scan': operation_scan,
        'ls': operation_ls
    }
    parser.add_argument('operation', default='scan', choices=operations.keys())
    parser.add_argument('--config', help='Config file', default='config.json')
    parser.add_argument('--deleted', help='Show deleted files (ls)', default=False, action='store_true')
    parser.add_argument('--verbose', help='Verbose logging', default=False, action='store_true')
    parser.add_argument('--add-dir', help='Add directory', nargs='*', dest='add_dir')
    args = parser.parse_args()

    logging.basicConfig(level=(logging.INFO if args.verbose else logging.WARNING))
    with open(args.config) as f:
        config = json.load(f)

    if args.add_dir:
        if len(args.add_dir) % 2:
            stderr.write('Bad --add-dir argument count\n')
            exit(1)
        config['directories'].update(chunk(args.add_dir))
            
    operations[args.operation](config, args)

def chunk(xs):
    i = iter(xs)
    for x in i:
        b = x
        yield (x, i.next())

if __name__ == '__main__':
    main()
