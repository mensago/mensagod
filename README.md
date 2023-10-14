# mensagod: server-side daemon for the [Mensago](https://mensago.org) online communications platform

mensagod provides identity services and data storage and synchronization for Mensago client applications. It is written in Go and is released under the MIT license. 

## Description

This is the reference implementation of the server for the Mensago platform. Its role is to provide message delivery services and user device synchronization.

The server daemon isn't dramatically different from other database-based applications. It sits on top of PostgreSQL, runs as a non-privileged user, stores files in a dedicated directory, and listens on the network. The main server code is written in Go, but ancillary utilities are written in Python to keep the build simple.

## Contributing

Although a mirror repository can be found on GitHub for historical reasons, the official repository for this project is on [GitLab](https://gitlab.com/mensago/mensagod). Please submit issues and pull requests there.

Mensago itself is a very young, very ambitious project that needs help in all sorts of areas -- not just writing code. Find out more information at https://mensago.org/develop.

### Environment Setup

Although the final product will have a very polished install experience, development setup is a bit more involved.

#### Prerequisites

- Supported version of the Go SDK
- A currently-supported version of PostgreSQL.

#### Setup

1. Create a PostgreSQL database and associated user with all permissions on said database. Make note of the password used to connect to this database.
2. Run the server executable in setup mode with root privileges.
	- If using the source tree directly, ```sudo go run `ls *.go` --setup``` works from bash in the repository root or from a PowerShell session with admin privileges, `go run $(ls *.go) --setup`.
	- Answer the setup questions. If unsure, the defaults will provide a safe, secure setup which assumes the database server runs on the same machine.
	- If your Postgres setup is non-standard (not localhost:5432, database name/user mensago/mensago), make the necessary adjustments to your database config
3. Once setup is completed successfully, run the server as the desired unprivileged user, for example, on Linux, ```sudo -u mensago go run `ls *.go` ```.

## Current Status and Roadmap

As of 10/2023, mensagod is developed enough to provide local message delivery and basic file synchronization. To reduce maintenance workload, the Python-based integration tests have been deprecated in favor of the Kotlin-based ones packaged with [Mensago Connect](https://gitlab.com/mensago/connect). Because development is just one person as of this writing, the current focus is on the client side until it has caught up sufficiently to warrant the finish work on mensagod.

Some of the remaining tasks to bring mensagod to a complete 1.0 status:

- Message delivery between servers
- Device checking
- Finish key lifecycle (rotation, revocation, etc.)
