
build:
	go build

clean: force
	rm -rf out

force:

test-with-bash: clean
	go run . bash

test-with-nonroot-user: clean
	go run . --user $(USER) -- bash -norc

test-with-hello: clean
	go run . -- go run ./hello

test-with-netcat-http: clean
	go run . -- bash -c "printf 'GET / HTTP/1.1\r\nHOST: example.com\r\nUser-Agent: nc\r\n\r\n' | nc 93.184.215.14 80 > out"

test-with-curl: clean
	go run . -v -- bash -c "curl -s http://example.com > out"

test-with-curl-https: clean
	go run . -v -- bash -c "curl -s https://example.com > out"

test-with-curl-monasticacademy: clean
	go run . -- bash -c "curl -sL http://monasticacademy.org > out"

test-with-curl-pre-resolved: clean
	go run . -- bash -c "curl -s --resolve example.com:80:93.184.215.14 http://example.com > out"

test-with-netcat-dns: clean
	go run . -- bash -c "echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r | socat udp4:1.1.1.1:53 - | xxd > out"

test-with-dig: clean
	go run . -- bash -c "dig -t a google.com > out"

test-with-dig-explicit-nameserver: clean
	go run . -- bash -c "dig -t a google.com @1.1.1.1 > out"

test-with-oci: clean
	go run . -- oci ce cluster generate-token --region us-ashburn-1 --cluster-id ocid1.cluster.oc1.iad.aaaaaaaauluvhw2v2emhebn4h724eedou76nhacixlczbj4emc52m44j4asq

test-with-webui-sleep-forever: clean
	go run . --webui :5000 -- sleep infinity

test-with-webui-curl-loop: clean
	go run . --webui :5000 -- bash -c "while true; do echo "curling..."; curl -s https://www.example.com > out; sleep 1; done"

test-with-netcat-11223: clean
	go run . --verbose -- bash -c "netcat example.com 11223 < /dev/null"

test-with-gcloud: clean
	go run . -- gcloud compute instances list

test-with-java: clean
	go run . -- java Example

test-with-doh: clean
	go run . -- curl --doh-url https://cloudflare-dns.com/dns-query https://www.example.com

test-with-js: clean
	go run . node js-experiment/get.js

test-with-self: clean
	go run . go run . curl https://www.example.com

# Test with running httptap in priveleged mode, and turning off creation of user namespace

test-with-sudo: clean
	go build -o /tmp/httptap .
	sudo /tmp/httptap bash

test-with-no-new-user-namespace: clean
	go build -o /tmp/httptap .
	sudo /tmp/httptap --no-new-user-namespace -- curl -so out https://www.example.com

test-with-setcap:
	go build -o /tmp/httptap
	sudo setcap 'cap_net_admin=ep cap_sys_admin=ep cap_dac_override=ep' /tmp/httptap
	/tmp/httptap --no-new-user-namespace -- curl -so out https://www.example.com

tcpdump-port-11223:
	sudo tcpdump -i lo 'tcp port 11223'
