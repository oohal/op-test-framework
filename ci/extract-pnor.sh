#!/bin/bash -ex

# if we have a cached copy then use the artifacts from that
if [ -f ci_cache/vmlinux ] && [ -f ci_cache/initramfs ] && [ -f ci_cache/skiboot.lid ] ; then
	cp ci_cache/{vmlinux,initramfs,skiboot.lid} .
	exit 0
fi

# grab a pnor - we should probably parameterise this.
if ! [ -f ./romulus.pnor ] ; then
	wget https://openpower.xyz/job/openpower/job/openpower-op-build/label=slave,target=romulus/lastSuccessfulBuild/artifact/images/romulus.pnor
fi

# build pflash
if ! [ -d skiboot/ ] ; then
	git clone https://github.com/open-power/skiboot.git --depth=1
fi

if ! [ -f skiboot/externals/pflash ] ; then
	make -C skiboot/external/pflash/ -j`nproc`
fi

# cleanup old files. We don't do this a the end of the script so that we can
# always inspect the entrails if the extracted images don't work.
rm -f tmp.* bootkernel* initramfs* vmlinux* skiboot.lid*

pflash="skiboot/external/pflash/pflash -F ./romulus.pnor"

# Extract skiboot. We could build a copy from the source tree we cloned above,
# but this is faster and I figure testing with images from the same PNOR is a
# good idea anyway.
$pflash -P PAYLOAD -r skiboot.lid.xz --skip=4096
unxz skiboot.lid.xz

# decompressing inside qemu is pretty slow, so we extract the kernel from the
# zImage manually and decompress it here.
$pflash -P BOOTKERNEL -r tmp.bootkernel --skip=4096
powerpc64-linux-gnu-objcopy --dump-section .kernel:vmlinux.strip=vmlinux.xz tmp.bootkernel
unxz vmlinux.xz

# And again for the initramfs. The kernel adds a size field to the end of the
# compressed image which we need to strip off. If we don't then unxz will barf
powerpc64-linux-gnu-objcopy --dump-section .init.ramfs=tmp.initramfs.xz ./vmlinux
size="$(wc -c < tmp.initramfs.xz)"
dd if=tmp.initramfs.xz of=initramfs.xz bs=$((size - 8)) count=1
unxz initramfs.xz

# now we need to stop the kernel from using it's builtin initramfs. To do that
# replace the contents of the .init.ramfs section with the default CPIO the
# kernel uses. We need to pad out the stub to the full section size since
# the kernel expects that.

stub_path="$(realpath $(dirname $0))/stub_initramfs"

dd if=/dev/zero of=tmp.padded bs=$size count=1
dd if=$stub_path of=tmp.padded conv=notrunc
powerpc64-linux-gnu-objcopy --update-section .init.ramfs=tmp.padded ./vmlinux

if [ -d "ci_cache" ] ; then
	cp ./vmlinux initramfs skiboot.lid ci_cache/
fi
