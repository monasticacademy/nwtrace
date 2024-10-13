
bash:
	make build
	.build/httptap bash

nonroot-bash:
	make build
	.build/httptap --user $(USER) -- bash -norc

test-with-hello:
	make build
	.build/httptap ./hi

test-with-netcat-http:
	rm -f out
	make build
	.build/httptap -- bash -c "printf 'GET / HTTP/1.1\r\nHOST: example.com\r\nUser-Agent: nc\r\n\r\n' | nc 93.184.215.14 80 > out"

test-with-curl:
	rm -f out
	make build
	.build/httptap -- bash -c "curl -s http://example.com > out"

test-with-curl-https:
	rm -f out
	make build
	.build/httptap -v -- bash -c "curl -s https://example.com > out"

test-with-curl-monasticacademy:
	rm -f out
	make build
	.build/httptap -- bash -c "curl -sL http://monasticacademy.org > out"

test-with-curl-pre-resolved:
	rm -f out
	make build
	.build/httptap -- bash -c "curl -s --resolve example.com:80:93.184.215.14 http://example.com > out"

test-with-netcat-dns:
	rm -f out
	make build
	.build/httptap -- bash -c "echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r | socat udp4:1.1.1.1:53 - | xxd > out"

test-with-dig:
	rm -f out
	make build
	.build/httptap -- bash -c "dig -t a google.com > out"

test-with-dig-explicit-nameserver:
	rm -f out
	make build
	.build/httptap -- bash -c "dig -t a google.com @1.1.1.1 > out"

test-with-oci:
	rm -rf out
	make build
	.build/httptap -- oci ce cluster generate-token --region us-ashburn-1 --cluster-id ocid1.cluster.oc1.iad.aaaaaaaauluvhw2v2emhebn4h724eedou76nhacixlczbj4emc52m44j4asq

test-with-sleep-forever:
	rm -rf out
	make build
	.build/httptap --webui :5000 -- sleep infinity

test-with-curl-loop:
	rm -rf out
	make build
	.build/httptap --verbose --webui :5000 -- bash -c "while true; do echo "curling..."; curl -s https://www.example.com > out; sleep 1; done"

build:
	mkdir -p .build
	go build -o .build/httptap
	sudo setcap 'cap_net_admin=ep cap_sys_admin=ep' .build/httptap
