# Go DTLS implementation

This is my work in progress DTLS implementation in pure Go.
It is not working at all yet, except for the client DH_anon handshake.

**Disclaimer: I'm very likely not qualified to write a secure implementation of DTLS.
While I do not write custom crypto I don't have knowledge about how to prevent timing attacks etc.
Aside from the fact that this implementation is generally not usable, I would also not recommend using it in any real projects even when it becomes theoretically usable.**

## TODO

* [x] Get encryption and decryption working for AES + SHA
* [ ] Implement handshake fragment reassembly
* [ ] Implement handshake timeout
* [ ] Handle out of order handshake messages
* [ ] Implement authenticated handshake
* [ ] Implement alert protocol
* [ ] Clean up the implementation
* [ ] Add tests
* [ ] Implement other cipher suites
* [ ] Maybe implement extensions
* [ ] Extend TODO list

## Currently not supported
Well .. mostly everything, but especially:

* Session resumption
* Renegotiation
