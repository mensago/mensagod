# Ansid: Anselus Identity Daemon

Ansid provides identity services for the Anselus communications platform and is released under the GPLv3 license. 

## Description

The code for Ansid was originally slated to be part of the Anselusd, the reference Anselus server. However, in the interests of scalability and usefulness as an identity and authentication provider, it was broken out into a separate service.

Unlike most multi-factor authentication solutions, Ansid is intended to be the identity provider, not the account on the third party service (Google, Facebook, etc.). As such, its primary purpose is not to serve as an MFA add-on. Providing a way for passwordless logins to third party services is secondary, but nonetheless important.

## Contributing

The Anselus platform is a very young, very ambitious project that needs help in all sorts of areas -- not just writing code. Find out more information at https://anselus.org/develop.

### Environment Setup

1. Create a task-specific user and group (default:anselus/anselus)
2. Create the workspace, configuration, and log file directories and grant read/write/execute permissions to the new user
	- Windows
		- Log/Config: C:\ProgramData\anselusd
		- Workspace: C:\ProgramData\anselus
	- POSIX
		- Log: /var/log/anselus
		- Config: /etc/anselusd
		- Workspace: /var/anselus
3. Set permissions on /etc/anselusd to root/anselus 660 or C:\ProgramData\anselusd to Full Control for Administrators and the Anselus user only. 
4. Create PostgreSQL database and grant all permissions to anselus user (default:anselus)
5. Copy sampleconfig.toml to /etc/anselusd/serverconfig.toml
6. Edit serverconfig.toml
	- Set the database username and password at minimum
	- If your Postgres setup is non-standard (not localhost:5432, database name/user anselus/anselus), make the necessary adjustments to your database config
7. Windows users will want to install the pycryptodome module in addition to the others

### Current Status and Roadmap

As of 10/2020, account registration and logins are complete and working, and most of the keycard code is written, having been ported over from Smilodon. Unit tests for the keycard code are making good progress.

- Finish unit tests for existing keycard code ported from Smilodon
- Keycard resolver code and command handling in worker threads
- File transfer and management code, unit tests, and command handling
- Device checking
