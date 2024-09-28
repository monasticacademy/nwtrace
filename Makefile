

test-with-netcat-http:
	make build
	rm -f out
	sudo /tmp/httptap -- bash -c "printf 'GET / HTTP/1.1\r\nHOST: example.com\r\nUser-Agent: nc\r\n\r\n' | nc 93.184.215.14 80 > out"

test-with-curl:
	make build
	rm -f out
	sudo /tmp/httptap -- bash -c "curl -s --resolve example.com:80:93.184.215.14 http://example.com > out"

test-with-netcat-dns:
	make build
	rm -f out
	sudo /tmp/httptap -- bash -c "echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r | socat udp4:1.1.1.1:53 - | xxd > out"

test-with-dig:
	make build
	rm -f out
	sudo /tmp/httptap -- bash -c "dig -t a google.com @1.1.1.1 > out"

build:
	go build -o /tmp/httptap