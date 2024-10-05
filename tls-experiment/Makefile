PORT := 19870

verify-with-openssl:
	openssl verify -verbose -x509_strict -CAfile ca.crt certificate.crt

showcerts:
	openssl s_client -connect 127.0.0.1:$(PORT) -servername example.com -showcerts

test-with-curl:
	CURL_CA_BUNDLE=ca.crt curl --connect-to example.com:443:localhost:$(PORT) https://example.com

test-with-python:
	REQUESTS_CA_BUNDLE=ca.crt python get.py $(PORT)

test-with-go:
	SSL_CERT_FILE=ca.crt go run ./get 127.0.0.1:$(PORT) example.com