# Changelog

What changes in each version. Newest first.

The release workflow takes the section matching the tag it is publishing and
uses it as the release text, so what you write here is what the person
downloading it reads.

## v1

First release.

Reads your machine and sorts what it finds by whether you can do anything
about it: a setting you can flip, a change that costs you something real, or
something burned into silicon that will never change.

**Windows, Linux and macOS.** Each reads the same ideas from a different
place: the registry and SMBIOS tables on Windows, `/sys` and `/proc` on
Linux, the IORegistry on macOS.

**It says where it looked.** Every finding names the registry key or the file
it came from, so nobody has to take the program's word for anything. A
finding is measured when the value was read, inferred when it was deduced
from something else and says so, and UNSEEN when the check could not look at
all. That last one is counted separately and called out, because a check that
quietly returns nothing looks exactly like a machine with nothing to report.

**It never writes and never opens a socket.** Both are checked by tests that
read the source, so they cannot rot into being untrue.

**Identifiers are masked** unless you pass `--reveal`, so a report you paste
into a bug thread does not carry your machine's fingerprints.

English and Spanish, with the report text in `messages/` where translating
never means touching Go.
