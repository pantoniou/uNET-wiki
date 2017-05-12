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

