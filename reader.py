import sys
import struct
import hashlib
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

if __name__ == '__main__':
    with open('key') as f:
        pk = RSA.importKey(f.read())
    with open(sys.argv[1]) as f:
        while True:
            header = f.read(5)
            if not header:
                print 'DONE'
                break
            t, length = struct.unpack('!bL', header)
            p = f.tell()
            print 'Segment: type %d, length: %d' % (t, length)
            if t == 1:
                subtype, h, size = struct.unpack('!b16sL', f.read(21))
                print '  File segment: type %d, hash %s, key length %d' % (subtype, ''.join('%02x'%ord(x) for x in h), size)
                if subtype == 1:
                    encrypted_key = f.read(size)
                    keys = PKCS1_OAEP.new(pk).decrypt(encrypted_key)
                    key, iv = keys[:16], keys[16:]
                    print '    Key:', ''.join('%02x'%ord(x) for x in key)
                    print '    IV: ', ''.join('%02x'%ord(x) for x in iv)
                    encrypted_payload = f.read(length-size-21)
                    padded = AES.new(key, mode=AES.MODE_CBC, IV=iv).decrypt(encrypted_payload)
                    actual = padded[:-ord(padded[-1])]
                    actual_hash = hashlib.md5(actual).digest()
                    print '    Payload is:', 'OK' if actual_hash == h else 'Broken'
                    if actual_hash == h:
                        print '+++ VALIDSEG', ''.join('%02x'%ord(x) for x in h)
            f.seek(p+length)
