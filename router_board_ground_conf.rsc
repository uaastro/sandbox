/interface bridge
add name=bridge protocol-mode=none
add auto-mac=yes fast-forward=no mtu=1500 \
    name=bridge-local port-cost-mode=short protocol-mode=none
add fast-forward=no mtu=1500 name=bridge2 port-cost-mode=short \
    protocol-mode=none
add fast-forward=no mtu=1500 name=bridge5 port-cost-mode=short \
    protocol-mode=none
/interface lte apn
set [ find default=yes ] ip-type=ipv4 use-network-apn=no
/interface wireless channels
add band=2ghz-b/g/n frequency=2312 list=MYCHAN2 name=2312 width=5
add band=2ghz-b/g/n frequency=2362 list=MYCHAN2 name=2362 width=5
add band=2ghz-b/g/n frequency=2392 list=MYCHAN2 name=2392 width=5
add band=2ghz-b/g/n frequency=2522 list=MYCHAN2 name=2522 width=5
add band=2ghz-b/g/n frequency=2582 list=MYCHAN2 name=2582 width=5
add band=2ghz-b/g/n frequency=2602 list=MYCHAN2 name=2602 width=5
add band=5ghz-a frequency=6180 list=MYCHAN name=6180 width=10
add band=5ghz-a frequency=4980 list=MYCHAN name=4980 width=10
add band=5ghz-a frequency=5900 list=MYCHAN name=5900 width=10
/interface wireless
set [ find default-name=wlan1 ] basic-rates-b=5.5Mbps channel-width=5mhz \
    country=no_country_set disabled=no frequency=2602 frequency-mode=\
    superchannel ht-basic-mcs=mcs-0,mcs-1 ht-supported-mcs=mcs-0,mcs-1 \
    installation=outdoor mode=ap-bridge noise-floor-threshold=-110 \
    nv2-security=enabled rate-set=configured rx-chains=0,1 scan-list=\
    2312,2360,2390,2520,2580,2602 ssid=MikroTik2 supported-rates-a/g=\
    6Mbps supported-rates-b=5.5Mbps tx-chains=0,1 tx-power=30 \
    tx-power-mode=all-rates-fixed wireless-protocol=nstreme
/interface wireless nstreme
set wlan1 disable-csma=yes enable-nstreme=yes
/interface wireless security-profiles
set [ find default=yes ] supplicant-identity=MikroTik
/ip ipsec proposal
set [ find default=yes ] enc-algorithms=aes-128-cbc
/ip pool
add name=pool2 ranges=192.168.82.10,192.168.82.254
add name=pool5 ranges=192.168.85.10,192.168.85.254
add name=dhcp_pool1 ranges=192.168.82.2-192.168.82.254
add name=dhcp_pool2 ranges=192.168.85.2-192.168.85.254
add name=basic ranges=192.168.88.10-192.168.88.253
/interface wireless nstreme-dual
add disable-csma=yes name=nstreme2 remote-mac=4C:5E:0C:51:09:80 rx-band=\
    5ghz-a rx-channel-width=5mhz rx-frequency=6080 rx-radio=*5 tx-band=\
    2ghz-b/g/n tx-channel-width=5mhz tx-frequency=2312 tx-radio=wlan1
/interface bridge port
add bridge=bridge-local hw=no ingress-filtering=no interface=ether1 \
    internal-path-cost=10 path-cost=10
add bridge=bridge-local ingress-filtering=no interface=nstreme2 \
    internal-path-cost=10 path-cost=10
add bridge=bridge5 interface=*5
add bridge=bridge-local interface=wlan1
/ip firewall connection tracking
set udp-timeout=10s
/ip settings
set max-neighbor-entries=8192
/ipv6 settings
set disable-ipv6=yes max-neighbor-entries=8192
/interface ovpn-server server
set auth=sha1,md5
/ip address
add address=192.168.82.1/24 interface=bridge-local network=192.168.82.0
add address=192.168.85.1/24 interface=bridge5 network=192.168.85.0
add address=192.168.89.1/24 comment=int-man interface=bridge-local \
    network=192.168.89.0
add address=10.3.11.1 interface=wg1 network=10.3.11.1
/ip dhcp-client
add interface=bridge-local
/ip dhcp-server
add address-pool=dhcp_pool1 authoritative=after-2sec-delay disabled=yes \
    interface=bridge2 lease-time=3d name=dhcp2
add address-pool=dhcp_pool2 authoritative=after-2sec-delay disabled=yes \
    interface=bridge5 lease-time=3d name=dhcp1
add address-pool=basic disabled=yes interface=bridge lease-time=14h \
    name=dhcp-basic
/ip dhcp-server network
add address=192.168.82.0/24 dns-server=192.168.82.1 gateway=192.168.82.1
add address=192.168.85.0/24 dns-server=192.168.85.1 gateway=192.168.85.1
add address=192.168.88.0/24 dns-server=192.168.88.1 gateway=192.168.88.1
/ip firewall nat
add action=masquerade chain=srcnat disabled=yes out-interface=\
    bridge-local
add action=masquerade chain=srcnat out-interface=wg1
/ip ipsec policy
set 0 dst-address=0.0.0.0/0 src-address=0.0.0.0/0
/ip ipsec profile
set [ find default=yes ] dpd-interval=2m dpd-maximum-failures=5
/ip route
add dst-address=10.3.0.0/19 gateway=wg1
/routing bfd configuration
add disabled=no interfaces=all min-rx=200ms min-tx=200ms multiplier=5
/system clock
set time-zone-autodetect=no
/system identity
set name=Ground
/system leds
set 0 interface=wlan1
add interface=*3 leds=,,,, type=wireless-signal-strength
add interface=*3 leds="" type=interface-transmit
add interface=*3 leds="" type=interface-receive
/system note
set show-at-login=no
/tool bandwidth-server
set authenticate=no
/tool sniffer
set filter-interface=wlan1