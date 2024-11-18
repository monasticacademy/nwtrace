
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

in-place-overlay:
	mkdir -p tmp
	sudo mount -t tmpfs none $(pwd)/tmp
	cp -r merged tmp/
	mkdir -p tmp/work
	sudo mount \
		overlay \
		$(shell pwd)/merged \
		-t overlay \
		-olowerdir=$(shell pwd)/merged,upperdir=$(shell pwd)/tmp/upper,workdir=$(shell pwd)/tmp/work

unmount:
	sudo umount $(shell pwd)/merged
