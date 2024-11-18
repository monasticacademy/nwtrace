
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
	go run . -- bash -c "env curl -s https://example.com > out"

test-with-curl-dump: clean
	go run . --dump -- bash -c "curl -s https://example.com > out"

test-with-curl-dump-homegrown: clean
	go run . --dump --stack=homegrown -- bash -c "curl -s https://example.com > out"

test-with-curl-non-tls: clean
	go run . -- bash -c "curl -s http://example.com > out"

test-with-curl-monasticacademy: clean
	go run . -- bash -c "curl -sL http://monasticacademy.org > out"

test-with-curl-pre-resolved: clean
	go run . -- bash -c "curl -s --resolve example.com:443:93.184.215.14 https://example.com > out"

test-with-curl-pre-resolved-non-tls: clean
	go run . -- bash -c "curl -s --resolve example.com:80:93.184.215.14 http://example.com > out"

# works with gvisor stack but not homegrown stack
test-with-wget: clean
	go run . -- wget https://example.com -O out

test-with-udp-11223: clean
	go run . -- bash -c "echo 'hello udp' | socat udp4:1.2.3.4:11223 - "

test-with-two-udp-packets: clean
	go run . -- bash -c "echo 'hello udp' | socat -t 2 udp4:1.2.3.4:11223 - ; echo 'hello again udp' | socat -t 2 udp4:1.2.3.4:11223 - "

test-with-socat-dns: clean
	go run . -- bash -c "echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r | socat udp4:1.1.1.1:53 - | xxd"

test-with-dig: clean
	go run . -- dig -t a google.com

test-with-dig-1111: clean
	go run . -- dig -t a google.com @1.1.1.1

test-with-nslookup: clean
	go run . -- nslookup google.com

test-with-oci: clean
	go run . -- oci ce cluster generate-token --region us-ashburn-1 --cluster-id ocid1.cluster.oc1.iad.aaaaaaaauluvhw2v2emhebn4h724eedou76nhacixlczbj4emc52m44j4asq

test-with-webui-sleep-forever: clean
	go run . --webui :5000 -- sleep infinity

test-with-webui-curl-loop: clean
	go run . --webui :5000 -- bash -c "while true; do echo "curling..."; curl -s https://www.example.com > out; sleep 1; done"

test-with-netcat-11223: clean
	go run . -- bash -c "netcat example.com 11223 < /dev/null"

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

test-with-docker: clean
	mkdir -p .build
	go build -o .build/httptap
	docker run \
		--interactive \
		--tty \
		--rm \
		--volume .:/src \
		--workdir /src \
		--cap-add CAP_SYS_ADMIN \
		--device /dev/net/tun:/dev/net/tun \
		ubuntu \
		.build/httptap --no-overlay -- curl -so out https://www.example.com

test-with-docker-alpine: clean
	mkdir -p .build
	CGO_ENABLED=0 go build -o .build/httptap
	docker run \
		--interactive \
		--tty \
		--rm \
		--volume .:/src \
		--workdir /src \
		--cap-add CAP_SYS_ADMIN \
		--device /dev/net/tun:/dev/net/tun \
		alpine/curl \
		.build/httptap --no-overlay -- curl -so out https://www.example.com

test-with-docker-distroless: clean
	mkdir -p .build
	CGO_ENABLED=0 go build -o .build/httptap
	CGO_ENABLED=0 go build -o .build/hi ./hello
	docker run \
		--interactive \
		--tty \
		--rm \
		--volume .:/src \
		--workdir /src \
		--cap-add CAP_SYS_ADMIN \
		--device /dev/net/tun:/dev/net/tun \
		gcr.io/distroless/static-debian12 \
		.build/httptap --no-overlay -- .build/hi

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

test-with-udp-experiment:
	go build -o /tmp/httptap
	go build -o /tmp/udp-experiment ./udp-experiment
	sudo /tmp/httptap /tmp/udp-experiment httptap 1.2.3.4:11223

tcpdump-port-11223:
	sudo tcpdump -i lo 'tcp port 11223'
