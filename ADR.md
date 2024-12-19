# ADR 1 : Seperation of Software

In the context of how users will interact with the different required functionality of the crypto,
I decided for the seperation of the program into three parts **(Karat Farmer, Daemon, Wallet)**.
Instead of combining the program into one large piece.
This was to achieve a flexible seperation of concerns. Users dedicate machines to exactly the functionality they need.
Users could want to run multiple miners connected to one daemon, or just a wallet connected to someone elses daemon, or just a daemon and wallet.
This also allows users to create their own implementations of each of the major components of the software without having to recreate the entire program. They can use existing daemon apis to, for example, make their own wallet while communicating with the exisitng daemon.
This accepts that having three seperate programs means communication through a REST API, which increases development time and complexity. However, the slight difficulty of designing an API does not detract from the flexibility that the listed seperation of concerns provides.

---

# ADR 2 : Rust

In the context of choosing a programming language for this topic
I decided for the Rust programming language due to its extremely high performance with modern syntax features
