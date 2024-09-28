

test-with-netcat:
	make build
	rm -f out
	sudo /tmp/httptap -- bash -c "printf 'GET / HTTP/1.1\r\nHOST: example.com\r\nUser-Agent: nc\r\n\r\n' | nc 93.184.215.14 80 > out"

test-with-curl:
	make build
	rm -f out
	sudo /tmp/httptap -- bash -c "curl -s --resolve example.com:80:93.184.215.14 http://example.com > out"

build:
	go build -o /tmp/httptap
	sudo setcap "cap_sys_admin=ep" /tmp/httptap