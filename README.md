# mensagod: server-side daemon for the [Mensago](https://mensago.org) online communications platform

**mensagod** (pronounced *mehn-sa-go-DEE*) provides identity services and data storage and synchronization for Mensago client applications. It is written in Kotlin and is released under the MIT license. 

## Description

This is the reference implementation of the server for the Mensago platform. Its role is to provide strong identity assurances, digital certificate hosting, message delivery services, and user device synchronization.

The server daemon isn't dramatically different from other database-based applications. It sits on top of PostgreSQL, runs as a non-privileged user, stores files in a dedicated directory, and listens on the network. Originally the code was written in Go, but is currently being rewritten in Kotlin for a number of reasons, among them, stability.

## Contributing

Although a mirror repository can be found on GitHub for historical reasons, the official repository for this project is on [GitLab](https://gitlab.com/mensago/mensagod). Please submit issues and pull requests there.

Mensago itself is a very young, very ambitious project that needs help in all sorts of areas -- not just writing code. Find out more information at https://mensago.org/develop.

## Current Status and Roadmap

As of 1/2024, the version in the main branch is developed enough to provide local message delivery and basic file synchronization, but isn't entirely stable or well-tested, despite efforts otherwise. The Kotlin rewrite reuses a lot of well-tested code from [Mensago Connect](https://gitlab.com/mensago/connect) and was started specifically because:

- Go has a nasty tendency for runtime errors
- Its error-handling leaves a lot to be desired
- Seems to have a fair amount of boilerplate
- Unit and integration testing capabilities are quite barebones out of the box

The goal is to write a stable, more-polished version which has feature parity.

Some of the remaining tasks to bring mensagod to a complete 1.0 status. A few features needed beyond the Go version's implementation level include: 

- Message delivery between servers
- Device management
- Finish key lifecycle (rotation, revocation, etc.)
