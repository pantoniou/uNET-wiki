# uNet for Linux

This document explains how to configure and run uNet on Linux.

This release supports:

* uNet entities and protocol as defined in the whitepaper "uNET: An Autonomous Network Architecture and Protocol For Modern Networks" version 19.
* Number of local and remote entities is only limited by available memory.
* Ethernet media type with a uNet specific protocol type.
* X.509 public key certificates and pcks8 private key format used.
* Certificate validation against trust chain.
* Encryption per link supported, AES + GCM for data transfer.
* Fragmentation per hop when packet size exceeds MTU.
* Configuration via file based configfs interface and netlink socket interface for IP bridging configuration.
* Inspection of system state via file based sysfs attributes
* Userspace AF_UNET socket supported for direct uNet communication.
* Extensive debugging facilities, selected on runtime.

## Certificate generation and signing

Before we begin, we will need to create certificates and a trust chain, please
follow this guide for setting up your own certificate signing authority: [OpenSSL Certificate Authority](https://jamielinux.com/docs/openssl-certificate-authority/index.html)

Write down the password of the intermediate authority certificate when you follow the guide.
 
We will need the certificates of the signing authorities (ca and intermediate) in DER form. By default PEM format certificates are generated, use the following snippet to convert to DER:

`$ openssl x509 -outform der -in <filename>.cert.pem -out <filename>.cert.der`

The certificate files you will need to convert and keep are `certs/ca.cert.der` and `intermediate/certs/intermediate.cert.der`

After you have all the steps done use the following script to create and sign uNet certificates:
```bash
#!/bin/sh
# unet-entity-create.sh
N=unet-$1
echo "Creating private key for ${N}"
openssl genrsa \
	-out intermediate/private/${N}.key.pem 2048
chmod 400 intermediate/private/${N}.key.pem
openssl pkcs8 -in intermediate/private/${N}.key.pem \
	-topk8 -nocrypt -outform DER \
	-out intermediate/private/${N}.key.pkcs8.der
chmod 400 intermediate/private/${N}.key.pkcs8.der
echo

echo "Creating certificate for ${N}"
openssl req -config intermediate/openssl.cnf \
	-key intermediate/private/${N}.key.pem \
	-new -sha256 -out intermediate/csr/${N}.csr.pem \
	-subj "/C=US/ST=California/L=Los Angeles/O=Disrupter/OU=uNet Project/CN=$1"
echo

echo "Signing certificate for ${N}"
openssl ca -config intermediate/openssl.cnf \
	-extensions server_cert -days 375 -notext -md sha256 \
	-in intermediate/csr/${N}.csr.pem \
	-out intermediate/certs/${N}.cert.pem
chmod 444 intermediate/certs/${N}.cert.pem
openssl x509 -outform der \
	-in intermediate/certs/${N}.cert.pem \
	-out intermediate/certs/${N}.cert.der
chmod 444 intermediate/certs/${N}.cert.der
echo

echo "Verifying certificate for ${N}"
openssl x509 -noout -text \
	-in intermediate/certs/${N}.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem \
      intermediate/certs/${N}.cert.pem
echo
```

You can create a new cert and private key pair by executing in the root of the CA signing directory (i.e. `~/ca`)
```
$ ./create-unet-entity.sh bob
```
It will put the public certificate and the private key in `intermediate/certs/unet-bob.cert.der` and `intermediate/private/unet-bob.key.pkcs8.der` respectively.

## Yocto binary toolchain setup

Get the yocto poky binary toolchain and qemu, and install it at the default directory `~/poky-sdk`
```
$ wget http://downloads.yoctoproject.org/releases/yocto/yocto-2.2/toolchain/x86_64/poky-glibc-x86_64-core-image-minimal-core2-64-toolchain-ext-2.2.sh
$ chmod a+x poky-glibc-x86_64-core-image-minimal-core2-64-toolchain-ext-2.2.sh
$ ./poky-glibc-x86_64-core-image-minimal-core2-64-toolchain-ext-2.2.sh
```

## uNet enabled Linux Kernel

The following snipper gets and builds the kernel for qemu testing on x86.
```
$ git clone git@github.com:andymilburn/uNET-Linux.git linux
$ cd linux
$ git checkout --track -b unet-crypto origin/unet-crypto
$ make unet_defconfig
$ make -j 8 bzImage
```

The resulting kernel image is located in `arch/x86_64/boot/bzImage`

## Using the provided images with QEMU

To ease testing a number of pre-made images with tools and configuration scripts have been provided.
The images are used with qemu and the kernel compiled as described previously, and use tap interfaces to communicate over a bridge. The bridge assumed in the scripts is named `br0`.
The name of the images are in the form `core-image-minimal-qemux86-64-tap<n>.ext4` where n is 1, 2, 3...

The following scripts create and destroy the bridge; note that by default no communication is possible with the host, if you need that you will need to add on of the host's interfaces (i.e. `eth0` to the bridge).

The `unet-create-bridge.sh` script that creates the bridge must be run before booting the images.
```bash
#!/bin/sh
# unet-create-bridge.sh
sudo brctl addbr br0
sudo ifconfig br0 up
```

The `unet-destroy-bridge.sh` script may be run to clean up.
```bash
#!/bin/sh
# unet-destroy-bridge.sh
sudo ifconfig br0 down
sudo brctl delbr br0
```

A number of scripts are provided that make booting the images easier:

The runqemu-tap-bridge script runs QEMU making sure that the mac address used every time is the same (to avoid problems when getting DHCP addresses and ssh-ing in).

```bash
#!/bin/bash
# runqemu-tap-bridge.sh
function genmac {

	local h=`hostname | md5sum | cut -f1 -d' '`
	local t=`echo $1 | md5sum | cut -f1 -d' '`

	local v0=`echo ${h} | cut -c1-2`
	local v1=`echo ${h} | cut -c3-4`
	local v2=`echo ${h} | cut -c5-6`
	local v3=`echo ${t} | cut -c1-2`
	local v4=`echo ${t} | cut -c3-4`
	local v5=`echo ${t} | cut -c5-6`

	local v=`printf "%d" 0x${v0}`

	# turn off multicast bit 0
	v=$((${v} & 254))
	# turn on locally administered bit
	v=$((${v} | 2))

	v0=`printf "%02x" $v`

	echo "$v0:$v1:$v2:$v3:$v4:$v5"
}

TAP=$1
IMG=$2
KERNEL=$3
if test "x${TAP}" == x ; then
	TAP=tap0
fi

if test "x${IMG}" == x ; then
	IMG=core-image-minimal-qemux86-64-tap1.rootfs.ext4
fi

if test "x${KERNEL}" == x ; then
	KERNEL=bzImage
fi

MAC=`genmac ${TAP}`

echo "Tap device name : ${TAP}"
echo "MAC address     : ${MAC}"
echo "Image file      : ${IMG}"
echo "Kernel image    : ${KERNEL}"

# create interface if it doesn't exit
/sbin/ifconfig >/dev/null 2>&1 ${TAP}
if ! /sbin/ifconfig >/dev/null 2>&1 ${TAP} ; then
	sudo tunctl -g `id -g` -t ${TAP}
fi

# QEMU="${HOME}/yocto/poky/build/tmp/sysroots/x86_64-linux/usr/bin/qemu-system-x86_64"
# KERNEL_APPEND="root=/dev/vda rw highres=off console=ttyS0 mem=256M vga=0 uvesafb.mode_option=640x480-32 oprofile.timer=1 uvesafb.task_timeout=-1"
# IFUP="${HOME}/yocto/poky/build/qemu_br0_ifup.sh"
# IFDOWN="${HOME}/yocto/poky/build/qemu_br0_ifdown.sh"

QEMU="${PWD}/tmp/sysroots/x86_64-linux/usr/bin/qemu-system-x86_64"
KERNEL_APPEND="root=/dev/vda rw highres=off console=ttyS0 mem=256M vga=0 uvesafb.mode_option=640x480-32 oprofile.timer=1 uvesafb.task_timeout=-1"
IFUP="${PWD}/qemu_br0_ifup.sh"
IFDOWN="${PWD}/qemu_br0_ifdown.sh"
set -x
${QEMU} \
	-nographic -cpu core2duo -m 256 \
	-device virtio-net-pci,netdev=net0,mac=${MAC} \
	-netdev tap,id=net0,ifname=${TAP},script=${IFUP},downscript=${IFDOWN} \
	-drive file=${IMG},if=virtio,format=raw \
	-vga vmware -show-cursor -usb -usbdevice tablet -device virtio-rng-pci \
	-kernel ${KERNEL} -append "${KERNEL_APPEND}"
```

This script uses the following interface up and interface down scripts which add and remove tap devices from the bridge we've created earlier:

```bash
#!/bin/bash
#qemu_br0_ifup.sh
switch=br0
echo "$0: adding tap interface \"$1\" to bridge \"$switch\""
sudo ifconfig $1 0.0.0.0 up
sudo brctl addif ${switch} $1
exit 0
```

```bash
#!/bin/bash
#qemu_br0_ifdown.sh
switch=br0
echo "$0: deleting tap interface \"$1\" from bridge \"$switch\""
sudo brctl delif $switch $1
sudo ifconfig $1 0.0.0.0 down
exit 0
```

And finally a script that simply requires the number of the image to run:

```bash
#!/bin/bash
#run-tap.sh
set -x
./runqemu-tap-bridge.sh tap${1} core-image-minimal-qemux86-64-tap${1}.ext4 bzImage
```

All of the scripts must be run from the `~/poky_sdk` directory we've installed yocto earlier.

## Running QEMU uNet images

Assuming the installation of the yocto binaries, the compilation of the kernel and the setup of `br0` bridge is complete, open two terminal instances and in both issue:

```
$ cd ~/poky_sdk
$ . environment-setup-core2-64-poky-linux
```

Run qemu on terminal #1 using:
```
$ ./run-tap.sh 1
```

And terminal #2 using:
```
$ ./run-tap.sh 2
```

You should get a login prompt at both terminals, the first one `qemux86-64-john` and the other `qemux86-64-alice`. John and Alice are the names of the entities we're going to create in each instance.

Log in using root at both.

Verify that unet support is built via:
```
root@qemux86-64-john:~# dmesg | grep unet
[   44.501778] unet: Starting (0.1)
[   44.503551] unet_socket_setup:
[   44.578451] unet: crypto alg #0 (gcm(aes)) is available
[   44.641540] unet: crypto alg #1 (authenc(hmac(sha256),ecb(aes))) is available
[   44.643409] unet: crypto alg #2 (authenc(hmac(sha256),ecb(aes))) is available
[   44.655089] unet_eth_bearer_register OK
[   44.663296] unet: uNet activated
```

Verify that the following files exist in instance #1:
```
root@qemux86-64-john:~# ls ca.cert.der intermediate.cert.der unet-john.cert.der unet-john.key.pkcs8.der 
ca.cert.der              intermediate.cert.der    unet-john.cert.der       unet-john.key.pkcs8.der
```

Similarly for instance #2:
```
root@qemux86-64-alice:~# ls ca.cert.der intermediate.cert.der unet-alice.cert.der unet-alice.key.pkcs8.der 
ca.cert.der               intermediate.cert.der     unet-alice.cert.der       unet-alice.key.pkcs8.der
```

Install the trust chain certificates in the order that matches their signing order in both instances.

```
# cat ~/intermediate.cert.der ~/ca.cert.der >/config/unet/trust_chain
```

syslog messages redirected to the console should be similar to:
```
[87055.993832] unet: Loading uNet trust-chain certificates
[87056.029466] unet: Loaded X.509 cert #0 'Konsulko Group Intermediate CA: 2bae11210d44b635448f8064a5aa69c21989e7da'
[87056.129731] alg: No test for pkcs1pad(rsa,sha256) (pkcs1pad(rsa-generic,sha256))
[87056.162346] unet: Loaded X.509 cert #1 'Konsulko Group: a23147d3a0c4879c5a18b83883fd4269171f2d37'
[87056.164452] unet: Trust chain contains #2 keys - verifying trust.
[87056.178628] unet: cert 'Konsulko Group Intermediate CA: 2bae11210d44b635448f8064a5aa69c21989e7da' (#0) verifies against 'Konsulko Group: a23147d3a0c4879c5a18b83883fd4269171f2d37' (#1)
```

Configure instance #1 as an entity named `0.123456`, forcing it to have `0.0` as a parent (meaning no parent) and installing it's certificate and private key.

Create the entity
```
root@qemux86-64-john:~# mkdir /config/unet/entities/0.123456
```

Force it's parent
```
root@qemux86-64-john:~# echo 0.0 >/config/unet/entities/0.123456/force_parent 
```

Install the private key
```
root@qemux86-64-john:~# cat ~/unet-john.key.pkcs8.der >/config/unet/entities/0.123456/privkey 
[87374.672773] unet: Loaded private key 'unet-0.123456'
```

Install the certificate
```
root@qemux86-64-john:~# cat ~/unet-john.cert.der >/config/unet/entities/0.123456/cert 
[87396.993501] unet: Loaded X.509 cert 'Disrupter: unet-john: 2b63382d2357d5ad98989c901a3eb3c282919a1f'
```

Do the same at instance #2, configuring it as `1.abcdef0` but forcing the parent to be `0.123456`

