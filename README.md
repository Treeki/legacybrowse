This is heavily unfinished.

I'm learning Rust and trying to write something incredibly cursed in the process. This is a HTTP proxy that man-in-the-middles your TLS connections and downgrades them to 1995's finest, SSLv2.

## "but why would you do this"

I like messing around with old tech. Many websites now require access through secure protocols - which is entirely understandable, but does mean you can't do silly things like try to load Twitter in Netscape 3 any more.

Browsers this old only really support SSLv2 (1995) and SSLv3 (1996). Both of these have been exiled from modern crypto libraries (for good reason!), but it does mean that you can't exactly rely on existing tools like mitmproxy.

So I've implemented it myself.

## Current Status

- figured out how to generate certificates that are compatible with IE4, Netscape 3, Opera 3 and hopefully other contemporary browsers
- implemented a rudimentary SSLv2 server library, supporting precisely one cipher spec (RC4 with export-grade 40-bit keys and MD5 MACs)
- drafted some HTTP proxy/tunnel code on top of tokio-rs (needs heavy refactoring)

## TODO

- make the HTTP proxy code not garbage
- support decryption of TLS connections (the whole point of this project)
- support more ciphers
- possibly add client support and make the SSLv2 library into a crate


