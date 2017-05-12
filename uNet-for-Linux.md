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

* Follow this guide for setting up your own certificate signing authority: [OpenSSL Certificate Authority](https://jamielinux.com/docs/openssl-certificate-authority/index.html)

* Write down the password of the intermediate authority certificate when you follow the guide.
 
* We will need the certificates of the signing authorities (ca and intermediate) in DER form. By default PEM format certificates are generated, use the following snippet to convert to DER:
    $ openssl x509 -outform der -in <filename>.cert.pem -out <filename>.cert.der


After you have all the steps done use the following script to create and sign uNet certificates:

