PORT := 44867

showcerts:
	echo "YOU MUST UPDATE THE PORT INT HE CURL COMMAND BELOW!"
	openssl s_client -connect 127.0.0.1:$(PORT) -servername example.com -showcerts

verify-with-openssl:
	openssl verify -verbose -x509_strict -CAfile ca.crt certificate.crt

test-with-curl:
	echo "YOU MUST UPDATE THE PORT INT HE CURL COMMAND BELOW!"
	curl --cacert ca.crt --connect-to example.com:443:localhost:$(PORT) https://example.com 