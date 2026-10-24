# Security policy

Version 0.1.x is the initial supported line. Do not include secrets, private
datasets, failure messages or credential-bearing URLs in public issues.

Use GitHub's **Security → Report a vulnerability** private reporting form when
available. If it is unavailable, open a public issue containing only a request
for a private reporting channel, without exploit details or sensitive data.

The tool works on local input and makes no network requests. Output omits source
values but may reveal filenames, field names, rule IDs or test identities. Review
these before sharing. Input limits constrain ordinary accidental oversized files;
this application is not an operating-system sandbox for hostile workloads.
