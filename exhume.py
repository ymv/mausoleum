from sys import stdin
from csv import reader
from os.path import join, dirname, exists
from os import makedirs
from mausoleum.slab import SlabFile
from MySQLdb import connect
from Crypto.PublicKey import RSA

def main():
    slabs_dir = '/media/Seagate Expansion Drive/Landfill/Slabs/'
    pk = RSA.importKey(open('stage/key').read())
    con = connect(db='mausoleum', charset='utf8')

    slabs = {}
    input = reader(stdin)
    s = 0
    for _domain, path, _updated, size, hashes in input:
        todo = []
        for h in hashes.split():
            c = con.cursor()
            c.execute('SELECT slab, offset FROM slab_segment WHERE hash=%s ORDER BY slab LIMIT 1', (h,))
            r = c.fetchone()
            if not r:
                print path
                print 'HASH NOT FOUND', h
                return
            todo.append(r+(h,))

        out = join("/home/me/EXHUME", path)
        if exists(out):
            continue
        out_dir = dirname(out)
        if not exists(out_dir):
            makedirs(out_dir)
        with open(out, 'w') as f:
            for slab, offset, hash_perf in todo:
                if slab not in slabs:
                    slabs[slab] = SlabFile(open(join(slabs_dir, slab)), pk)
                slabf = slabs[slab]

                slabf.seek(offset)
                hash, payload, _ = slabf.read()

                hash_hex = ''.join('%02x' % ord(c) for c in hash)
                if hash_hex != hash_perf:
                    print path
                    print 'SHIT IN SLAB', hash_hex, ' need ', hash_perf
                    return

                f.write(payload)
        s+=int(size)
    print fmt(s)

def fmt(x):
    r = []
    for s in ['', 'Ki','Mi','Gi']:
        v = x % 1024
        if v:
            r.append(str(v) + s)
        x = x / 1024
        if not x:
            break
    return ' '.join(reversed(r))
if __name__ == '__main__':
    main()
