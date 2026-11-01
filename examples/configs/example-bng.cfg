# jan/01/2020 00:00:00 by RouterOS 6.49.10
# model = CCR2004-1G-12S+2XS
/system identity
set name=example-bng
/ip dns set servers=8.8.8.8,1.1.1.1
/ip firewall address-list
add list=snmp address=198.51.100.9
/ip firewall filter
add chain=input action=accept protocol=udp dst-port=161 src-address-list=snmp
add chain=input action=drop
/routing bgp instance
set default as=64512 router-id=192.0.2.1 redistribute-connected=yes
/routing bgp peer
add name=border remote-address=192.0.2.2 update-source=192.0.2.1 remote-as=64512 in-filter=FROM-BORDER out-filter=TO-BORDER
/routing filter
add chain=FROM-BORDER prefix=0.0.0.0/0 prefix-length=0 action=accept
add chain=FROM-BORDER action=discard
add chain=TO-BORDER prefix=203.0.113.0/24 prefix-length=25-32 action=accept
add chain=TO-BORDER action=discard
