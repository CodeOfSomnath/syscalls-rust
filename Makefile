
all:
	rm -rf ./docs
	cargo doc --no-deps
	echo "<meta http-equiv=\"refresh\" content=\"0; url=syscalls-rust\">" > target/doc/index.html
	cp -r target/doc ./docs
