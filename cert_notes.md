Creating a root certificate:

	openssl req -x509 -nodes -newkey rsa:1024 -md5 -keyout root.key -set_serial 5 -config cert.cnf -out root.pem
	openssl x509 -in root.pem -outform der -out root.crt




Import new cert:

https://web.archive.org/web/20000619094136/http://www.entrust.net:80/customer/generalinfo/import.htm
