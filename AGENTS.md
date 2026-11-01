Use jujutsu (jj) in this repo.

**NEVER** mount anything over an existing mount, especially a user's home
directory.
**NEVER** carry out destructive writes to pre-existing or unrelated files in a
user's home directory.
**NEVER** carry out destructive operations as root - this is a read-only tool!
Use LXC for any tests that could impact the wider system.
