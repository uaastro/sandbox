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
#local-address=10.168.144.8 (={tunnel_id}*2)
#remote-address=10.168.144.9 (={tunnel_id}*2+1)
#tunnel-id=4
add local-address=10.168.144.8 mac-address=02:8C:01:2D:99:6E name=\
    eoip-wg remote-address=10.168.144.9 tunnel-id=4
/interface wireless security-profiles
set [ find default=yes ] supplicant-identity=MikroTik
/interface bridge port
add bridge=local-bridge interface=eoip-wg
add bridge=local-bridge interface=lan
/interface wireguard peers
add allowed-address=0.0.0.0/0 endpoint-address=wg.trackersinfo.com \
    endpoint-port=13231 interface=wg_field is-responder=yes name=peer1 \
    persistent-keepalive=25s public-key=\
    "z7+gEPaiiiFAy7Mje6KhkE66iFPS54o94YGZ7lT08U0="
/ip address
add address=192.168.144.2/24 comment="LAN subnet" interface=local-bridge \
    network=192.168.144.0
#to change:
#address=10.168.144.8/24 (=tunnel_id*2)
add address=10.168.144.8/24 interface=wg_field network=10.168.144.0
/ip dhcp-client
add interface=wan use-peer-dns=no
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
#set name=#4-field (=#{tunnel_id}-field)
set name=#4-field
/system note
set show-at-login=no