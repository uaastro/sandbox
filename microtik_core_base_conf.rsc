/interface ethernet
set [ find default-name=ether16 ] name=WAN
/interface wireguard
add listen-port=13231 mtu=1420 name=wg_core
/port
set 0 name=serial0
/interface wireguard peers
add allowed-address=10.168.144.2/32 comment=#1 interface=wg_core name=\
    #1-field public-key="HdURE+JM1ILlfF5ssA+2k1nkD7JSCGYbimDRggdn3EU="
add allowed-address=10.168.144.3/32 interface=wg_core name=#1-gs \
    public-key="+xwzB7/Fi2ZJwel3H3SPQ6EI9k49eAvPJ6tyXUr+pkc="
add allowed-address=10.168.144.5/32 interface=wg_core name=#2-gs \
    persistent-keepalive=25s public-key=\
    "vtqmX995bCTLFj/NVAitnO69wG6ywXwMvNg7lQzja0o="
add allowed-address=10.168.144.4/32 comment=#2 interface=wg_core name=\
    #2-field public-key="CwmocjgOVV4bJwBLBe0jOPyqquCYZe664Hb/PTCTVmc="
add allowed-address=10.168.144.7/32 interface=wg_core name=#3-gs \
    public-key="4XdZfyLv23tASd9xai9s1AGyolaij+oDsS89mMImdQw="
add allowed-address=10.168.144.6/32 comment=#3 interface=wg_core name=\
    #3-field public-key="bi3zd6SsJwg5AN1kCgKg3Zn/Q/FmGA83QLp1QiGY5nA="
add allowed-address=10.168.144.9/32 interface=wg_core name=#4-gs \
    persistent-keepalive=25s public-key=\
    "aXmRr8RwiJ5GwwkIXcN6ZL2XQNe+sdDsuJyPxWYSbGM="
add allowed-address=10.168.144.8/32 comment=#4 interface=wg_core name=\
    #4-field persistent-keepalive=25s public-key=\
    "zgTALm3/ytCW2PadZ1RtC6aIiarILunM8W8hQmz85gs="
/ip address
add address=91.206.30.84/24 interface=WAN network=91.206.30.0
add address=10.168.144.1/24 comment=wg_core interface=wg_core network=\
    10.168.144.0
/ip dns
set allow-remote-requests=yes servers=\
    8.8.8.8,194.0.200.115,178.20.153.153
/ip firewall filter
add action=accept chain=input comment="Accept established/related" \
    connection-state=established,related
add action=drop chain=input comment="Drop invalid" connection-state=\
    invalid
add action=accept chain=input comment="Allow Winbox" dst-port=8291 \
    protocol=tcp
add action=accept chain=input comment="Allow SSH" dst-port=22 protocol=\
    tcp
add action=accept chain=input comment="Allow ping" protocol=icmp
add action=accept chain=input comment="Allow local traffic" \
    in-interface=!WAN
add action=accept chain=input comment="Allow WireGuard" dst-port=13231 \
    in-interface=WAN protocol=udp
add action=drop chain=input comment="Drop all other input"
/ip route
add gateway=91.206.30.254
/system clock
set time-zone-name=Europe/Kiev
/system identity
set name=tbm_wg_core
/system note
set show-at-login=no
/system routerboard settings
set enter-setup-on=delete-key