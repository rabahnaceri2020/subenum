# Subdomain wordlists

## Default: SecLists top 5,000

The bundled [subdomains.txt.gz](<subdomains.txt.gz>) contains an unchanged copy of
[`Discovery/DNS/subdomains-top1million-5000.txt`](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-top1million-5000.txt)
from **SecLists**, maintained by Daniel Miessler and the SecLists contributors.
See the [upstream license](https://github.com/danielmiessler/SecLists/blob/master/LICENSE).

- Entries: **5,000**, one candidate per line, in upstream order.
- Uncompressed size: **30,075 bytes**.
- Verified against the official download captured on **2026-11-06**.
- Uncompressed SHA-256:
  `e331367c140298cb179114fdeefa78f58f696219f0dec017a28bb79487cfcf19`.
- Raw upstream URL:
  <https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt>.

The archive is tracked in Git; the expanded plaintext is a local runtime artifact
and is ignored by Git. Fresh clones expand this compact archive. If the archive
is absent, [the installer](<../../install.sh>) fetches the same SecLists list from
upstream. An existing nonempty plaintext list is preserved, including custom
lists and older installations' 200,000-entry lists; updating Git alone does not
replace those local files.

The bundled archive is a pinned snapshot. An unbundled install's download follows
the upstream `master` version, which may change over time.

### Rebuilding the archive reproducibly

After obtaining the verified plaintext, run from the repository root:

```python
from pathlib import Path
import gzip
import hashlib
import io

source = Path("resources/wordlists/subdomains.txt").read_bytes()
assert hashlib.sha256(source).hexdigest() == (
    "e331367c140298cb179114fdeefa78f58f696219f0dec017a28bb79487cfcf19"
)
compressed = io.BytesIO()
with gzip.GzipFile(filename="", fileobj=compressed, mode="wb", compresslevel=9, mtime=0) as stream:
    stream.write(source)
Path("resources/wordlists/subdomains.txt.gz").write_bytes(compressed.getvalue())
```

This omits the filename and timestamp from the gzip header. Offline regression
checks in [test_wordlist.py](<../../tests/test_wordlist.py>) validate the snapshot,
archive reproducibility, and installer behavior with downloads mocked.

## Deep mode

The `--deep` wordlist remains separate and unchanged: the installer obtains
[`n0kovo_subdomains_huge.txt`](https://github.com/n0kovo/n0kovo_subdomains/blob/main/n0kovo_subdomains_huge.txt)
from **n0kovo_subdomains**, maintained by n0kovo and contributors. The compact
SecLists default does not replace or truncate that separate deep-mode runtime
list.
