# Notes
debian_notes

### IP

```
cat <<EOF > /etc/network/interfaces
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
source /etc/network/interfaces.d/*
# The loopback network interface
auto lo
iface lo inet loopback
# The primary network interface
auto ens192
#allow-hotplug ens192
#iface ens192 inet dhcp
iface ens192 inet static
address 192.168.88.105
netmask 255.255.255.0
gateway 192.168.88.1
#up route add -net xxx.xxx.x.0 netmask 255.255.255.0 gw 192.168.96.254
#down route del -net xxx.xxx.x.0 netmask 255.255.255.0 gw 192.168.96.254
#
#
#
EOF
```
