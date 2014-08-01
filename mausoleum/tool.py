from argparse import ArgumentParser
from os import stat, walk
from os.path import join, relpath
from sys import stderr, exit, stdout
import json
import logging
from magic import Magic
from zlib import compress
from MySQLdb import connect
from Crypto.PublicKey import RSA
from mausoleum.repository import Repository
from mausoleum.segment_repository import SegmentRepository
from mausoleum.stat import Timer
from mausoleum.slab import SlabFile
from hashlib import md5
from itertools import groupby
from csv import writer

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
            print (u'%-*s %-*s %d %d' % (max_domain, domain, max_len, fn, ts or 0, size or 0)).encode('utf-8')

def operation_index(config, args):
    with open(config['key']) as f:
        pk = RSA.importKey(f.read())
    total = total_cmp = 0
    for slab in args.slabs:
        print 'SLAB', slab
        with open(slab, 'r') as rf:
            f = SlabFile(rf, pk)
            while True:
                pos = f.tell()
                x = f.read()
                if x is None:
                    print 'SLAB-END'
                    break
                hash, data, format = x
                print 'SEGMENT', pos, ''.join('%02x' % ord(c) for c in hash), len(data), format
                if args.validate:
                    actual_hash = md5(data).digest()
                    print '  VALIDATION:', 'OK' if hash == actual_hash else 'FAIL'
                if args.appraise:
                    compressed_l = len(compress(data))
                    print '  COMPRESS: %d (%.2f%%)' % (compressed_l, 100.0*compressed_l/len(data))
                    total += len(data)
                    total_cmp += compressed_l

    if args.appraise:
        print 'TOTAL COMPRESS: %d (%.2f%%)' % (total-total_cmp, 100.0*total_cmp/total)

def operation_exhumation_prepare(config, args):
    con = connect(db=config['database'], charset='utf8')
    c = con.cursor()
    sql = """
        SELECT f.id, f.domain, f.path, f.state, f.updated, fs.hash
        FROM file f
        JOIN file_segment fs ON fs.file_id = f.id
    """
    where = []
    params = []
    if args.domain:
        where.append("f.domain IN (" + ','.join(['%s']*len(args.domain)) + ')')
        params += args.domain
    if args.deleted:
        where.append("f.state != %s")
        params.append("deleted")
    else:
        where.append("f.state = %s")
        params.append("active")
    if where:
        sql += '\nWHERE\n' + ' AND\n'.join(where)
    sql += "\nORDER BY f.domain, f.seen, fs.i"
    c.execute(sql, params)

    out = writer(stdout)
    files = {}
    dedup = {}
    for i, ((file_id, domain, path, state, updated), subrows) in enumerate(groupby(c, lambda r: r[:-1])):
        hashes = ' '.join(r[-1] for r in subrows)
        if args.dedup:
            dedup[(domain, path)] = hashes, (i if args.dedup == 'newest' else len(path))
        files[(domain, path)] = [domain.encode('utf-8'), path.encode('utf-8'), updated, hashes]

    if args.dedup:
        survivors = {}
        for (domain, path), (hashes, weight) in dedup.iteritems():
            k = (domain, hashes)
            if k not in survivors:
                survivors[k] = path, weight
            else:
                path_old, weight_old = survivors[k]
                if weight_old < weight:
                    del files[(domain, path_old)]
                    survivors[k] = path, weight
                else:
                    del files[(domain, path)]

    for row in files.itervalues():
        out.writerow(row)

def main():
    parser = ArgumentParser(description='Mausoleum archival tool')
    operations = {
        'scan': operation_scan,
        'ls': operation_ls,
        'index': operation_index,
        'exhumation_prepare': operation_exhumation_prepare
    }
    parser.add_argument('operation', default='scan', choices=operations.keys())
    parser.add_argument('--config', help='Config file', default='config.json')
    parser.add_argument('--deleted', help='Show deleted files (ls, exhumation_prepare)', default=False, action='store_true')
    parser.add_argument('--verbose', help='Verbose logging', default=False, action='store_true')
    parser.add_argument('--add-dir', help='Add directory', nargs='*', dest='add_dir')
    parser.add_argument('slabs', help='Slabs (index)', nargs='*')
    parser.add_argument('--validate', help='Validate segments (index)', default=False, action='store_true')
    parser.add_argument('--appraise', help='Appraise segment compression (index)', default=False, action='store_true')
    parser.add_argument('--domain', help='Domain (exhumation_prepare)', nargs='*')
    parser.add_argument('--dedup', help='Deduplication (exhumation_prepare)', choices=['newest', 'longest'])
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
    Timer.report()

def chunk(xs):
    i = iter(xs)
    for x in i:
        b = x
        yield (x, i.next())

if __name__ == '__main__':
    main()
