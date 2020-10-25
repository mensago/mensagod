# anselusd: server-side daemon for the [Anselus](https://anselus.org) online communications platform

anselusd, which will eventually have a better name, provides identity services and data storage and synchronization for Anselus client applications and is released under the MIT license. 

## Description

Yeah, yeah, everyone says that they are the "next-generation online communications platform," but no one has had the guts to try to replace e-mail. No one has, that is, until now. Frankly, though, it's not just e-mail, it's Outlook, Facebook, and Twitter.

The server daemon isn't dramatically different from other database-based applications. It sits on top of PostgreSQL, runs as a non-privileged user, stores files in a dedicated directory, and listens on the network. The main server code is written in Go, but ancillary utilities are written in Python to keep the build simple.

## Contributing

Anselus is a very young, very ambitious project that needs help in all sorts of areas -- not just writing code. Find out more information at https://anselus.org/develop.

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
- File synchronization
- Message delivery
- Device checking
