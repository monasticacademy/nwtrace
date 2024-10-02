
bash:
	go build -o /tmp/httptap
	sudo /tmp/httptap bash

nonroot-bash:
	go build -o /tmp/httptap
	sudo /tmp/httptap --user $(USER) -- bash -norc

test-with-hello:
	go build -o /tmp/httptap
	sudo /tmp/httptap ./hi

test-with-netcat-http:
	rm -f out
	go build -o /tmp/httptap
	sudo /tmp/httptap -- bash -c "printf 'GET / HTTP/1.1\r\nHOST: example.com\r\nUser-Agent: nc\r\n\r\n' | nc 93.184.215.14 80 > out"

test-with-curl:
	rm -f out
	go build -o /tmp/httptap
	sudo /tmp/httptap -- bash -c "curl -s --resolve example.com:80:93.184.215.14 http://example.com > out"

test-with-netcat-dns:
	rm -f out
	go build -o /tmp/httptap
	sudo /tmp/httptap -- bash -c "echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r | socat udp4:1.1.1.1:53 - | xxd > out"

test-with-dig:
	rm -f out
	go build -o /tmp/httptap
	sudo /tmp/httptap -- bash -c "dig -t a google.com @1.1.1.1 > out"

test-with-oci:
	rm -rf out
	go build -o /tmp/httptap
	sudo /tmp/httptap -- oci ce cluster generate-token --region us-ashburn-1 --cluster-id ocid1.cluster.oc1.iad.aaaaaaaauluvhw2v2emhebn4h724eedou76nhacixlczbj4emc52m44j4asq

build:
	go build -o /tmp/httptap
