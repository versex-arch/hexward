# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem in hexward itself.
Use GitHub's private reporting instead: the **Security** tab of this repository → **Report a vulnerability**.

Include what you found, how to reproduce it and which version (`hexward --version`) you used.
You will get an answer as soon as possible; fixes are released before the details are published.

## Scope

In scope: anything that lets hexward be used against the person running it, for example

- a crafted log line, file name or file that makes it execute code, write outside its data folder or hide a finding
- a way for another program, web page or machine on the network to reach the local window server or read its token
- quarantine restoring a file somewhere other than where it came from

Out of scope: malware that hexward does not detect (it is a heuristic tool and says so), and attacks that
require the attacker to already run code as the same user.

## Supported versions

Only the latest release receives fixes.
