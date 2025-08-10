/interface bridge
add name=bridge protocol-mode=none
add name=bridge-local
add name=bridge2
/interface wireless
set [ find default-name=wlan1 ] band=2ghz-b/g/n channel-width=5mhz \
    country=no_country_set disabled=no frequency=auto frequency-mode=\
    superchannel mode=station-pseudobridge name=wlan1-gateway \
    noise-floor-threshold=-110 nv2-security=enabled rx-chains=0,1 \
    scan-list=2602,2362,2392,2522,2582,2312 ssid=MikroTik2 tx-chains=0,1 \
    wireless-protocol=nstreme
/interface wireless nstreme
set wlan1-gateway enable-nstreme=yes
/interface wireless channels
add band=2ghz-b/g/n frequency=2312 list=MYCHAN2 name=2312 width=5
add band=2ghz-b/g/n frequency=2362 list=MYCHAN2 name=2362 width=5
add band=2ghz-b/g/n frequency=2392 list=MYCHAN2 name=2392 width=5
add band=2ghz-b/g/n frequency=2522 list=MYCHAN2 name=2522 width=5
add band=2ghz-b/g/n frequency=2582 list=MYCHAN2 name=2582 width=5
add band=2ghz-b/g/n frequency=2602 list=MYCHAN2 name=2602 width=5
/interface wireless security-profiles
set [ find default=yes ] supplicant-identity=MikroTik
/ip pool
add name=defaul-dhcp ranges=192.168.88.10-192.168.88.253
/ip dhcp-server
add address-pool=defaul-dhcp interface=bridge-local lease-time=14h name=\
    dhcp-default
/interface bridge port
add bridge=bridge-local interface=wlan1-gateway
add bridge=bridge-local interface=ether1
/ip address
add address=192.168.82.2/24 interface=bridge-local network=192.168.82.0
/ip dhcp-client
add disabled=yes interface=bridge-local
/ip dhcp-server network
add address=192.168.88.0/24 gateway=192.168.88.2
/ip firewall nat
add action=masquerade chain=srcnat out-interface=bridge-local
/ip route
add dst-address=0.0.0.0/0 gateway=192.168.82.1
/system identity
set name=912_Board
/system note
set show-at-login=no
/tool sniffer
set filter-interface=ether1