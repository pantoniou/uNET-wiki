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

Please create a symbolic link to the bzImage first

```
# ln -s ~/linux/arch/x86_64/boot/bzImage ~/poky_sdk/
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

```
root@qemux86-64-alice:~# mkdir /config/unet/entities/1.abcdef0
root@qemux86-64-alice:~# echo 0.123456 >/config/unet/entities/1.abcdef0/force_parent 
root@qemux86-64-alice:~# cat ~/unet-alice.key.pkcs8.der >/config/unet/entities/1.abcdef0/privkey 
[ 1427.064292] unet: Loaded private key 'unet-1.abcdef0'
root@qemux86-64-alice:~# cat ~/unet-alice.cert.der >/config/unet/entities/1.abcdef0/cert 
[ 1438.455527] unet: Loaded X.509 cert 'Disrupter: unet-alice: e139d194eeef20fbb19ee5d5e719ffc7665f1ac0'
```

If you want at this point you can enable debugging for a lot of debugging messages:

```
# for i in /sys/unet/unet_syslog_*dump; do echo 1 >$i; done
```

Enable the instances; #1 first

```
# echo 1 >/config/unet/entities/0.123456/enable
```

And #2
```
# echo 1 >/config/unet/entities/1.abcdef0/enable
```

If you've enabled debugging you should see a lot of messages, and in the end
on instance #2 you should have the state of the entity change to `registered`

```
root@qemux86-64-alice:~# cat /sys/unet/local-entities/1.abcdef0/state 
registered
```

The state of #1 is unregistered (cause the parent is forced to `0.0`)

Test that communication of ping (echo-req & echo-rep) messages works:

```
root@qemux86-64-alice:~# echo 0.123456 hello >/sys/unet/local-entities/1.abcdef0/ping 
root@qemux86-64-alice:~# [ 2094.050917] unet: 1.abcdef0: ERP 6 bytes [68656c6c6f0a] (hash 11dd729f)
```

Note that that 68656c6c6f0a is a hexdump of hello+newline

## uNet user-space sockets - unet-chat

To verify the user-space uNet socket interface we'll use unet-chat from
[uNet Hello World](https://github.com/andymilburn/unet-helloworld)

The full source of unet-chat.c is:

```c
/*
 * unet-chat
 *
 * Simple chat using unet sockets
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <getopt.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "unet-common.h"

bool server_mode = true;
const char *server_id = "app.chat";
uint32_t message_type = 1200;	/* hardcoded */

static const char usage_synopsis[] = "unet-chat [options] <server-address>";
static const char usage_short_opts[] = "m:i:hv";
static struct option const usage_long_opts[] = {
	{ "mt",			required_argument, NULL, 'm'},
	{ "id",			required_argument, NULL, 'i'},
	{ "help",		no_argument,       NULL, 'h'},
	{ "version",		no_argument,       NULL, 'v'},
	{ NULL,			no_argument,       NULL, 0x0},
};

static const char * const usage_opts_help[] = {
	"\n\tMessage type (default is 1200)",
	"\n\tApplication id (default is app.chat)",
	"\n\tPrint this help and exit",
	"\n\tPrint version and exit",
	NULL,
};

static void usage(const char *errmsg)
{
	print_usage(errmsg, usage_synopsis, usage_short_opts,
			usage_long_opts, usage_opts_help);
}

int main(int argc, char *argv[])
{
	int s, err, opt, optidx, len;
	struct sockaddr_unet server_sa, peer_sa, self_sa, in_sa;
	char *server_ua_txt = NULL, *peer_ua_txt = NULL, *self_ua_txt = NULL, *p;
	socklen_t slen;
	fd_set rfds;
	bool connected = false;
	char line[256], buf[65536];

	while ((opt = getopt_long(argc, argv, usage_short_opts,
				  usage_long_opts, &optidx)) != EOF) {
		switch (opt) {
		case 'm':
			message_type = atoi(optarg);
			break;
		case 'i':
			server_id = optarg;
			break;
		case 'v':
			printf("Version: %s\n", PACKAGE_VERSION);
			exit(EXIT_SUCCESS);
		case 'h':
			usage(NULL);
		default:
			usage("unknown option");
		}
	}

	if (optind < argc)
		server_mode = false;

	memset(&server_sa, 0, sizeof(server_sa));
	server_sa.sunet_family = AF_UNET;
	server_sa.sunet_addr.message_type = message_type;
	err = unet_str_to_addr(server_id, strlen(server_id), &server_sa.sunet_addr.addr);
	if (err == -1) {
		fprintf(stderr, "bad server id (%s) provided (%d:%s)\n",
				server_id, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	s = socket(AF_UNET, SOCK_DGRAM, 0);
	if (s == -1) {
		perror("Failed to open unet socket (is unet enabled in your kernel?)");
		exit(EXIT_FAILURE);
	}

	if (server_mode) {

		server_ua_txt = unet_addr_to_str(&server_sa.sunet_addr.addr);
		if (!server_ua_txt) {
			perror("failed on unet_addr_to_str()");
			exit(EXIT_FAILURE);
		}
		printf("server binding to '%s'\n", server_ua_txt);

		free(server_ua_txt);

		server_ua_txt = NULL;

		err = bind(s, (struct sockaddr *)&server_sa, sizeof(server_sa));
		if (err == -1) {
			fprintf(stderr, "failed to bind using %s server_id (%d:%s)\n",
					server_id, errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		connected = false;
	} else {

		len = asprintf(&server_ua_txt, "%s:%s", argv[optind], server_id);

		server_sa.sunet_family = AF_UNET;
		server_sa.sunet_addr.message_type = message_type;
		err = unet_str_to_addr(server_ua_txt, strlen(server_ua_txt), &server_sa.sunet_addr.addr);
		if (err == -1) {
			fprintf(stderr, "bad full server address (%s) provided (%d:%s)\n",
					server_ua_txt, errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		err = connect(s, (struct sockaddr *)&server_sa, sizeof(server_sa));
		if (err == -1) {
			fprintf(stderr, "failed to connect to full server address (%s) (%d:%s)\n",
					server_ua_txt, errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		/* now get sockname to get the full address */
		memset(&peer_sa, 0, sizeof(peer_sa));
		slen = sizeof(peer_sa);
		err = getpeername(s,(struct sockaddr *)&peer_sa, &slen);
		if (err == -1) {
			perror("failed on getpeername()");
			exit(EXIT_FAILURE);
		}

		peer_ua_txt = unet_addr_to_str(&peer_sa.sunet_addr.addr);
		if (!peer_ua_txt) {
			perror("failed on unet_addr_to_str()");
			exit(EXIT_FAILURE);
		}

		connected = true;
	}

	/* now get sockname to get the full address */
	memset(&self_sa, 0, sizeof(self_sa));
	slen = sizeof(self_sa);
	err = getsockname(s, (struct sockaddr *)&self_sa, &slen);
	if (err == -1) {
		perror("failed on getsockname()");
		exit(EXIT_FAILURE);
	}

	self_ua_txt = unet_addr_to_str(&self_sa.sunet_addr.addr);
	if (!self_ua_txt) {
		perror("failed on unet_addr_to_str()");
		exit(EXIT_FAILURE);
	}

	printf("Welcome to unet-chat; %s '%s'\n",
			server_mode ? "listening for clients in" : "using server",
			server_mode ? self_ua_txt : server_ua_txt);
	printf("\r%s > ", self_ua_txt);
	fflush(stdout);

	FD_ZERO(&rfds);
	for (;;) {
		FD_SET(STDIN_FILENO, &rfds);
		FD_SET(s, &rfds);

		err = select(s + 1, &rfds, NULL, NULL, NULL);
		if (err == -1) {
			perror("select() failed");
			exit(EXIT_FAILURE);
		}
		/* no data (probably EAGAIN) */
		if (err == 0)
			continue;

		/* line read */
		if (FD_ISSET(STDIN_FILENO, &rfds)) {
			p = fgets(line, sizeof(line) - 1, stdin);
			if (p) {
				line[sizeof(line) - 1] = '\0';
				len = strlen(line);
				while (len > 0 && line[len-1] == '\n')
					len--;
				line[len] = '\0';

				if (!connected)
					continue;

				len = send(s, p, strlen(p), 0);
				if (len == -1) {
					perror("failed to send\n");
					exit(EXIT_FAILURE);
				}
			}

			printf("%s > ", self_ua_txt);
			fflush(stdout);

		} else if (FD_ISSET(s, &rfds)) {
			/* first server packet */

			slen = sizeof(in_sa);
			len = recvfrom(s, buf, sizeof(buf) - 1, 0,
					       (struct sockaddr *)&in_sa, &slen);
			if (len > 0) {
				buf[len] = '\0';

				slen = sizeof(in_sa);

				if (!connected) {
					memcpy(&peer_sa, &in_sa, sizeof(in_sa));

					peer_ua_txt = unet_addr_to_str(&peer_sa.sunet_addr.addr);
					if (!peer_ua_txt) {
						perror("failed on unet_addr_to_str()");
						exit(EXIT_FAILURE);
					}

					err = connect(s, (struct sockaddr *)&peer_sa, sizeof(peer_sa));
					if (err == -1) {
						fprintf(stderr, "failed to connect to peer address (%s) (%d:%s)\n",
								peer_ua_txt, errno, strerror(errno));
						exit(EXIT_FAILURE);
					}

					fprintf(stderr, "\nconnection from (%s)\n", peer_ua_txt);

					connected = true;
				}

				/* do no allow more than one connection */
				if (!unet_addr_eq(&peer_sa.sunet_addr.addr, &in_sa.sunet_addr.addr))
					continue;

				printf("\r%*s\r%s> %s\n", 80, "", peer_ua_txt, buf);

				printf("%s > ", self_ua_txt);
				fflush(stdout);
			}
		}
	}

	close(s);

	if (server_ua_txt)
		free(server_ua_txt);
	if (peer_ua_txt)
		free(peer_ua_txt);
	if (self_ua_txt)
		free(self_ua_txt);

	return 0;
}
```

Note how similar to a standard UDP based application the source code is, that is the main point of the socket API interface.

Go to the terminal of instance #1 and enable the `app.chat` endpoint (in the current uNet security model applications do not have rights to create application endpoints).

```
root@qemux86-64-john:~# mkdir /config/unet/apps/app.chat
root@qemux86-64-john:~# echo 1 >/config/unet/apps/app.chat/enable 
```

Start `unet-chat` in server mode

```
root@qemux86-64-john:~# unet-chat 
server binding to 'app.chat'
Welcome to unet-chat; listening for clients in '0.123456:app.chat'
0.123456:app.chat > 
```

Go to instance #2 and start `unet-chat` in client mode.

```
root@qemux86-64-alice:~# unet-chat 0.123456
Welcome to unet-chat; using server '0.123456:app.chat'
1.abcdef0:#.0 > 
```

Typing in one instance now results in output generated at the other.
Use Ctrl-C to exit.

If you have debugging enabled you will note that every packet exchange is encrypted as it should.

## uNet IP bridging

It is possible to configure a point to point IP link over unet. This requires a [unet enabled iproute2](https://github.com/pantoniou/iproute2/tree/unet)

On instance #1 issue:

```
root@qemux86-64-john:~# ip link add name unet0 type unet local-entity 0.123456 remote-entity 1.abcdef0
root@qemux86-64-john:~# ip link set dev unet0 up
root@qemux86-64-john:~# ip route add 10.10.0.0/16 dev unet0
root@qemux86-64-john:~# ip address add 10.11.0.1/16 dev eth0
```

This creates a tunneling unet0 interface, installs a route at it (10.10.0.0/16) which also adding an alias address (10.11.0.1/16) on eth0.

On instance #2 issue:

```
root@qemux86-64-alice:~# ip link add name unet0 type unet local-entity 1.abcdef0 remote-entity 0.123456
root@qemux86-64-alice:~# ip link set dev unet0 up
root@qemux86-64-alice:~# ip route add 10.11.0.0/16 dev unet0
root@qemux86-64-alice:~# ip address add 10.10.0.1/16 dev eth0
```

This creates a tunneling unet0 interface, installs a route at it (10.11.0.0/16) which also adding an alias address (10.10.0.1/16) on eth0.

We can now ping the IP address of the other end; on instance #1.

```
root@qemux86-64-john:~# ping -c 1 10.10.0.1
PING 10.10.0.1 (10.10.0.1): 56 data bytes
64 bytes from 10.10.0.1: seq=0 ttl=64 time=78.127 ms

--- 10.10.0.1 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 78.127/78.127/78.127 ms
```

While on instance #2

```
root@qemux86-64-alice:~# ping -c 1 10.11.0.1
PING 10.11.0.1 (10.11.0.1): 56 data bytes
64 bytes from 10.11.0.1: seq=0 ttl=64 time=68.493 ms

--- 10.11.0.1 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 68.493/68.493/68.493 ms
```

## configfs options

Configuration for unet is performed via the configfs filesystem.

The root unet configuration directory is `/config/unet` and the available configuration options are:

Timeouts

* `apca_timeout` Number of milliseconds to wait collecting APCA replies before moving to register. Default value is 500ms.
* `apcr_max_timeout` Maximum timeout for exponential backoff of APCR messages. Default value is 250ms.
* `apcr_min_timeout` Minimum timeout for exponential backoff of APCR messages. Default value is 30000ms (30 sec).
* `child_idle_timeout` Period of inactivity until a child is moved to non-connected state. Default value is 30000ms (30 sec).
* `housekeeping_timeout` Period of housekeeping activity. Smaller values increase CPU time but increase fidelity. Default value is 1000ms (1 sec).
* `keepalive_period` Period after which we request a keepalive. Default value is 1000ms (1 sec).
* `register_timeout` Period after which we resend a register request. Default value is 500ms.
* `reject_backoff` Period of time we honor a previous register reject. Default value is 30000ms (30 sec).

Counters

* `keepalive_max` Number of keepalives sent before declaring peer is unreachable. Default value is 3.
* `register_retries` Number of retries when sending a register message. Default value is 3.

Boolean switches

* `children_count_policy` If true, top bits of score is 32-log2(children-count). Default value is true.
* `random_score_policy` If true, the lower 32 bits of score is randomly generated. If false it's a hash of the address of the sender. Default value is false.
* `strict_hierarchical_routing` If true only communicate which attached peers (parent and children). If false any visible entity may be directly accessed. Default is true. Note that encryption requires this to be true.
* `force_relay_da_upstream` If true forward DAs even from known originators. Default is false.
* `force_relay_rfdr_upstream` If true forward RFDRs even from known originators. Default is false.
* `only_forward_from_valid_senders` If true, only forward from valid senders. Default is true.
* `relay_disconnect_announce_upstream` If true, forward all DAs upstream. Default is false.
* `try_reconnect_to_children` If true, send reconnect to all children when entity is registered. Default is true.

Trust certicates
* `trust_chain` The trust chain of the host. Default is empty.

Entities are created by issuing mkdir in the `entities/` directory.

Valid configuration options of the entity are:

* `id` binary override for id. Default is generated by parsing the name of the directory.
* `prefix` binary override for prefix. Default is generated by parsing the name of the directory.
* `can_be_router` If true entity advertises self as router. Default is true.
* `dev_class` Class of the entity, by default is 2 (LINUX Box).
* `force_parent` Forced parent of the entity. Default is empty.
* `cert` The X.509 certificate of the entity. Default is empty.
* `privkey` The PKCS8 private key of the entity. Default is empty.
* `enable` If true, the entity is enabled. Default is false. This must be set as true as last step of configuration.

App entries are created by issuing mkdir in the `apps/` directory.

Valid configuration options of the app entry are:

* `id` binary override for id. Default is generated by parsing the name of the directory.
* `prefix` binary override for prefix. Default is generated by parsing the name of the directory.
* `enable` If true, the app entry is enabled. Default is false. This must be set as true as last step of configuration.

All other not listed attributes are for debugging purposes only and may be removed at any time.
