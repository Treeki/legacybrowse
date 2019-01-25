Creating a root certificate:

	openssl req -x509 -nodes -newkey rsa:1024 -md5 -keyout root.key -set_serial 5 -config cert.cnf -out root.pem
	openssl x509 -in root.pem -outform der -out root.crt




Import new cert:

https://web.archive.org/web/20000619094136/http://www.entrust.net:80/customer/generalinfo/import.htm



What's going on:

IE requires a .crt; Opera requires a .pem; Netscape requires a .crt but silently fails to load it half the time for some reason (?!)


Analysing the Entrust certificates:

IE cert:

- Thawte root
- Valid 1/8/1996 to 31/12/2020
- Serial number 1
- Thumbprint 23e594945195f2414803b4d564d2a3a3f5d88b8c
- Enhanced key usage: server auth, code signing
- Basic constraints: CA, no path length constraint

- Accepted by IE4
- Shows owner (C, S, L, O, OU, CN, Email), issuer (C, S, L, O, OU, CN, Email), serial number 01, fingerprint 07:EE:23:01:EC:17:E3:1B:EE:A2:53:43:1A:15:CF:EA
- Accepted by NS3 (loosely)
- Accepted by Opera (as PEM)

NS cert:

- Entrust CA, issued by Thawte
- Valid 26/5/1999 to 25/5/2003
- Serial number 9
- Thumbprint b7ddcbb9a241c9b505e0dc72fd6db94424f4b8cf
- Enhanced key usage: server auth
- Basic constraints: CA, path length constraint = 0

- Denied by IE4 (empty popup box)
- Accepted by NS3 (loosely)
- Accepted by Opera (as PEM)

