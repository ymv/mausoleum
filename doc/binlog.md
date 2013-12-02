Binary log
==========

Binary file, big-endian. All numbers are unsigned

Stores file updates and removals, can be used to regenerate files database. Consist of concatenated records.
Each record starts with header:

<table>
  <tr><th>Length</th><th>Description</th></tr>
  <tr><td>4</td><td>Record length (including this header) (LENGTH)</td></tr>
  <tr><td>1</td><td>Record type: 1-new/updated file, 2-deleted file</td></tr>
  <tr><td>4</td><td>Record creation timestamp (correspond to file.seen field in database)</td></tr>
  <tr><td>1</td><td>Domain length (DOMAIN)</td></tr>
  <tr><td>2</td><td>Path length (PATH)</td></tr>
  <tr><td>DOMAIN</td><td>Domain (file.domain)</td></tr>
  <tr><td>PATH</td><td>Path (file.path)</td></tr>
</table>

Update record
-------------

Record new or updated file

<table>
  <tr><th>Length</th><th>Description</th></tr>
  <tr><td>4</td><td>File mtime (correspond to file.updated field in database)</td></tr>
  <tr><td>8</td><td>File size (correspond to file.size field in database)</td></tr>
  <tr><td>1</td><td>Mime length (MIME)</td></tr>
  <tr><td>MIME</td><td>Mime type</td></tr>
  <tr><td>2</td><td>Segment count (NSEG)</td></tr>
  <tr><td>NSEG * 16</td><td>Segment hashes</td></tr>
</table>

Delete record
-------------

No additional data, just header
