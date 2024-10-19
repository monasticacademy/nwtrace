
build: force
	rm -rf out
	mkdir -p .build
	go build -o .build/httptap
	sudo setcap 'cap_net_admin=ep cap_sys_admin=ep cap_dac_override=ep' .build/httptap

force:

bash: build
	.build/httptap bash

sudo-bash: build
	sudo .build/httptap bash

nonroot-bash: build
	.build/httptap --user $(USER) -- bash -norc

test-with-hello: build
	.build/httptap ./hi

test-with-netcat-http: build
	.build/httptap -- bash -c "printf 'GET / HTTP/1.1\r\nHOST: example.com\r\nUser-Agent: nc\r\n\r\n' | nc 93.184.215.14 80 > out"

test-with-curl: build
	.build/httptap -v -- bash -c "curl -s http://example.com > out"

test-with-curl-https: build
	.build/httptap -v -- bash -c "curl -s https://example.com > out"

test-with-curl-monasticacademy: build
	.build/httptap -- bash -c "curl -sL http://monasticacademy.org > out"

test-with-curl-pre-resolved: build
	.build/httptap -- bash -c "curl -s --resolve example.com:80:93.184.215.14 http://example.com > out"

test-with-netcat-dns: build
	.build/httptap -- bash -c "echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r | socat udp4:1.1.1.1:53 - | xxd > out"

test-with-dig: build
	.build/httptap -- bash -c "dig -t a google.com > out"

test-with-dig-explicit-nameserver: build
	.build/httptap -- bash -c "dig -t a google.com @1.1.1.1 > out"

test-with-oci: build
	.build/httptap -- oci ce cluster generate-token --region us-ashburn-1 --cluster-id ocid1.cluster.oc1.iad.aaaaaaaauluvhw2v2emhebn4h724eedou76nhacixlczbj4emc52m44j4asq

test-with-webui-sleep-forever: build
	.build/httptap --webui :5000 -- sleep infinity

test-with-webui-curl-loop: build
	.build/httptap --webui :5000 -- bash -c "while true; do echo "curling..."; curl -s https://www.example.com > out; sleep 1; done"

test-with-netcat-11223: build
	.build/httptap --verbose -- bash -c "netcat example.com 11223 < /dev/null"

test-with-gcloud: build
	.build/httptap -- gcloud compute instances list

test-with-java: build
	.build/httptap -- java Example

test-with-doh: build
	.build/httptap -- curl --doh-url https://cloudflare-dns.com/dns-query https://www.example.com

test-with-js: build
	.build/httptap node js-experiment/get.js

netcat-experiment:
	netcat localhost 11223 < /dev/null

tcpdump-port-11223:
	sudo tcpdump -i lo 'tcp port 11223'
