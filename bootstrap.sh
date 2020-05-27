#!/bin/bash -e

if ! [ -f qemu/ppc64-softmmu/qemu-system-ppc64 ] ; then
	if ! [ -d qemu ] ; then
		git clone https://github.com/qemu/qemu.git --depth=1
	fi
	cd qemu
	./configure --target-list=ppc64-softmmu
	make -j`nproc`
	cd ..
fi

if ! [ -d op-test-venv ] ; then
	python3 -m venv op-test-venv
	source op-test-venv/bin/activate
	pip3 install -r ./requirements.txt
	pip3 install . -e
fi

if ! [ -f ./qemu.conf ] ; then
	cat - > qemu.conf <<EOF
[op-test]
bmc_type=qemu
qemu_binary=qemu/ppc64-softmmu/qemu-system-ppc64
flash_skiboot=selftests/test_data/skiboot.lid.nophbs
flash_kernel=selftests/test_data/vmlinux
flash_initramfs=selftests/test_data/petitfs
EOF
fi

source op-test-venv/bin/activate
pytest --config-file ./qemu.conf -k boot_to_petitboot

