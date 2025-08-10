/interface bridge
add name=local-bridge
/interface ethernet
set [ find default-name=ether2 ] name=lan
set [ find default-name=ether1 ] name=wan
/interface wireless
set [ find default-name=wlan1 ] ssid=MikroTik
/interface wireguard
add listen-port=13231 mtu=1420 name=wg_field
/interface eoip
#to change:
#local-address=10.168.144.9 (={tunnel-id}*2+1)
#remote-address=10.168.144.8 (={tunnel-id}*2) 
#tunnel-id=4
add local-address=10.168.144.9 mac-address=02:6C:C5:36:6F:08 name=\
    eoip-wg remote-address=10.168.144.8 tunnel-id=4
/interface wireless security-profiles
set [ find default=yes ] supplicant-identity=MikroTik
/ip pool
add name=dhcp_pool_lan ranges=192.168.144.200-192.168.144.254
/interface bridge port
add bridge=local-bridge interface=eoip-wg
add bridge=local-bridge interface=lan
/interface wireguard peers
add allowed-address=0.0.0.0/0 endpoint-address=wg.trackersinfo.com \
    endpoint-port=13231 interface=wg_field is-responder=yes name=peer1 \
    persistent-keepalive=25s public-key=\
    "z7+gEPaiiiFAy7Mje6KhkE66iFPS54o94YGZ7lT08U0="
/ip address
add address=192.168.144.1/24 comment="LAN subnet" interface=local-bridge \
    network=192.168.144.0
#to change:
#address=10.168.144.9/24 (={tunnel-id}*2+1)
add address=10.168.144.9/24 interface=wg_field network=10.168.144.0
/ip dhcp-client
add interface=wan use-peer-dns=no
/ip dhcp-server
add address-pool=dhcp_pool_lan interface=local-bridge lease-time=1h \
    name=dhcp_lan
/ip dhcp-server network
add address=192.168.144.0/24 dns-server=8.8.8.8 gateway=192.168.144.2
/ip dns
set servers=8.8.8.8
/ip firewall filter
add action=accept chain=input comment="Allow EST/REL" connection-state=\
    established,related
add action=drop chain=input comment="Drop invalid" connection-state=\
    invalid
add action=accept chain=input comment="Allow ICMP" protocol=icmp
add action=accept chain=input comment="Allow LAN access" in-interface=\
    local-bridge
/ip firewall nat
add action=masquerade chain=srcnat comment="NAT LAN->WAN" out-interface=\
    wan
/system clock
set time-zone-name=Europe/Kiev
/system identity
#to change:
#set name=#4-gs (=#{tunnel-id}-gs)
set name=#4-gs
/system note
set show-at-login=no