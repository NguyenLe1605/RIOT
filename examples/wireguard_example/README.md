wireguard_example
=================

- The source code of Wireguard device driver is located at: `drivers/wireguard`.
- NOTE: the current implementation is still hacky in various way, but the implementer is busy at work right now.

Usage
=====

Describe here how to use this application

- Create the tap interface:

```bash
sudo ip tuntap add tap0 mode tap user ${USER}
sudo ip link set tap0 up
```

- Set up the network namespace that contains the Linux Wireguard interface.

```bash
sudo ./veth.sh
```

- Check the IPv6 address on the Wireguard namespace:

```bash
❯ sudo ip -n ns1 a show
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: veth1@if50: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether c6:01:30:60:18:30 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 2001:db8:100::2/128 scope global 
       valid_lft forever preferred_lft forever
    inet6 fe80::c401:30ff:fe60:1830/64 scope link 
       valid_lft forever preferred_lft forever
```

- The `privatekey`, the `publickey` file contains the the private and the public key for the wireguard-go interface. To generate a fresh key pair, do the following. Note that changing this key configuration requires to change the public key in the `main.c` example, and the private key configuration in the `conf` file.

```bash
wg genkey | tee privatekey | wg pubkey > publickey
```


- On a different terminal, clone, build and run `spoof`, a raw tunnel that will direct the packet from the tap interface to the Wireguard interface:

```bash
git clone git@github.com:NguyenLe1605/spoof.git
cd spoof
cargo build
sudo ./target/debug/spoof
```

- Clone and set up `wireguard-go` on another terminal, if there is no `wireguard-go` on your system yet and copy the wireguard configuration from the wireguard example folder.

```bash
git clone git@github.com:WireGuard/wireguard-go.git
cd wireguard-go
cp ${WIREGUARD_EXAMPLE}/conf .
```

- Build the `wireguard-go` executable

```bash
make
```


- On the wireguard terminal, create 2 terminals, one to set up and run wireguard interface, 1 for the `nc` application program. Set up the wireguard interface as the following:

```bash
sudo ip netns exec ns1 bash
LOG_LEVEL=debug ./wireguard-go -f wg0
```

- On the other terminals, set up the `wg0` interface by adding the IP address, set up the interface configuration and set the interface up, and turn on the `nc` program.

```bash
sudo ip netns exec ns1 bash
ip addr add fd00::1/8 dev wg0
wg setconf wg0 conf
ip link set wg0 up
nc -lu6 fd00::1 12345
```

- Back to the Wireguard example folder, run the example, now at the `nc` terminal, if succeed, a hello packet will send back to the netcat, and the reader can use it to send back only 1 packet from the netcat to the running Wireguard on RIOT. Wireshark can be used to inspect on either the `tap0` interface or the `veth` interface to check the correctness of the Wireguard packets.

```bash
PORT=tap0 make all term
```


