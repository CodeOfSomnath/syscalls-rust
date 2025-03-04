
all:
	cargo doc --no-deps
	mkdir -p ./docs/0.2.7
	# echo "<meta http-equiv=\"refresh\" content=\"0; url=/0.2.7/syscalls_rust\">" > docs/index.html
	cp -r target/doc/* ./docs/0.2.7/
