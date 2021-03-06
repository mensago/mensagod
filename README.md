# mensagod: server-side daemon for the [Mensago](https://mensago.org) online communications platform

mensagod provides identity services and data storage and synchronization for Mensago client applications and is released under the MIT license. 

## Description

Yeah, yeah, everyone says that they are the "next-generation online communications platform," but no one has had the guts to try to replace e-mail. No one has, that is, until now. Frankly, though, it's not just e-mail, it's Outlook, Facebook, and Twitter.

The server daemon isn't dramatically different from other database-based applications. It sits on top of PostgreSQL, runs as a non-privileged user, stores files in a dedicated directory, and listens on the network. The main server code is written in Go, but ancillary utilities are written in Python to keep the build simple.

## Contributing

Mensago is a very young, very ambitious project that needs help in all sorts of areas -- not just writing code. Find out more information at https://mensago.org/develop.

### Environment Setup

1. Create PostgreSQL database and associated user with all permissions on said database
2. Run utils/serverconfig.py
	- Set the database username and password at minimum
	- If your Postgres setup is non-standard (not localhost:5432, database name/user mensago/mensago), make the necessary adjustments to your database config
3. Windows users may need to install the pycryptodome module in addition to the others to use all the utilities

### Current Status and Roadmap

As of 2/2021, the most important bits of the Identity Services layer are complete, which includes private and public registration modes, preregistration, and logging in. Smaller bits (device key rotation, password updates, etc.) are in development.

Stuff which will be written once the IS layer is completed:

- File transfer and management code, unit tests, and command handling
- File synchronization
- Message delivery
- Device checking
