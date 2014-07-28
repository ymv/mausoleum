Slab file
=========

Binary file, big-endian values

Consists of multiple segments. Each segments starts with header, determining it's type and total length:

<table>
  <tr><th>Length</th><th>Description</th></tr>
  <tr><td>1</td><td>Segment type: <ul><li>1 - data segment</li><li>2 - compressed data segment</li></ul></td></tr>
  <tr><td>4</td><td>Segment length (without this header) (LENGTH)</td></tr>
</table>

Data segment
------------

Type 1 or 2

<table>
  <tr><th>Length</th><th>Description</th></tr>
  <tr><td>1</td><td>Encryption type, now always 1</td></tr>
  <tr><td>16</td><td>Payload hash</td></tr>
  <tr><td>4</td><td>Symmetric key ciphertext length (N)</td></tr>
  <tr><td>N</td><td>Symmetric key ciphertext</td></tr>
  <tr><td>LENGTH-N-21</td><td>Encrypted payload</td></tr>
</table>

If type is 2, payload is gzip compressed before encryption

Payload is encrypted using AES-128/CBC with random key and IV, using following padding:

<code>
pad = 16 - len(payload) % 16;

padded = payload + chr(pad) * pad
</code>

Key and IV are concatinated and encrypted using PKCS1-OAEP, producing symmetric key ciphertext
