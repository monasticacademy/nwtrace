
default: run

run:
	go build -o /tmp/overlay
	sudo /tmp/overlay

overlay:
	sudo mount \
		overlay \
		$(shell pwd)/merged \
		-t overlay \
		-olowerdir=$(shell pwd)/lower,upperdir=$(shell pwd)/upper,workdir=$(shell pwd)/work

unmount:
	sudo umount $(shell pwd)/merged
