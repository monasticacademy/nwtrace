ADB := $(HOME)/Downloads/platform-tools/adb

root:
	$(ADB) root

shell:
	$(ADB) shell

push:
	CGO_ENABLED=0 go build -o httptap ..
	$(ADB) push httptap /data/local/tmp/httptap

run-emulator:
	docker run -it --rm \
		-p 5555:5555 \
		-p 5554:5554 \
		-p 6080:6080 \
		-e EMULATOR_DEVICE="Samsung Galaxy S10" \
		-e WEB_VNC=true \
		--device /dev/kvm \
		--name android-container \
		budtmo/docker-android:emulator_11.0
