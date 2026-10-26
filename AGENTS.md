Use jujutsu (jj) in this repo.

**NEVER** mount anything over an existing mount e.g. /home/archie/
**NEVER** carry out any destructive writes to pre-existing or unrelated
files in /home/archie/
**NEVER** carry out destructive operations as root - this is a read-only
tool!
Use LXC for any tests that could impact the wider system.
