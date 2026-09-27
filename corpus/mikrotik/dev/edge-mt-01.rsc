# sep/27/2026 12:00:00 by RouterOS 6.22
# software id = NRKS-0001
#
# NIRIKSHAK corpus — SYNTHETIC. Written by Team Atlantis; not captured from a
# real device. The demo fixture for bootstrapping a vendor with no pack
# (ADR 0067): MikroTik RouterOS, which no pack describes.
#
# Provenance : every command below is a form shown in MikroTik's RouterOS
#              documentation (help.mikrotik.com). Most sections are written in
#              the /export shape that Configuration Management shows (a section
#              path at column zero, then the `add` or `set` command run there,
#              properties in alphabetical order); the three /ip service lines
#              are the full-path commands First Time Configuration prints,
#              verbatim. First Time Configuration also supplies the bridge,
#              addressing, input filter, ssh hardening, neighbour discovery and
#              mac-server commands; Identity and NTP the rest. No line changes
#              a documented command into a form the documentation does not show.
# Addressing : RFC 1918 (192.168.88.0/24, the documentation's own) and
#              RFC 5737. No credentials: no user or password line at all.
/interface bridge
add name=bridge1
/interface bridge port
add bridge=bridge1 interface=ether2
/ip address
add address=192.168.88.1/24 interface=bridge1
add address=203.0.113.100/24 interface=ether1
/ip firewall filter
add action=accept chain=input comment="accept established,related,untracked" connection-state=established,related,untracked
add action=drop chain=input comment="drop invalid" connection-state=invalid
add action=accept chain=input comment="accept ICMP" in-interface=ether1 protocol=icmp
add action=accept chain=input comment="allow SSH" in-interface=ether1 port=22 protocol=tcp
add action=drop chain=input comment="block everything else" in-interface=ether1
/ip neighbor discovery-settings
set discover-interface-list=LAN
/ip service disable telnet,ftp,www,api
/ip service set ssh port=2200
/ip service set winbox address=192.168.88.0/24
/ip ssh
set strong-crypto=yes
/system identity
set name=edge-mt-01
/system ntp client
set enabled=yes
/system ntp client servers
add address=192.0.2.10
add address=192.0.2.11
/tool mac-server
set allowed-interface-list=LAN
/tool mac-server mac-winbox
set allowed-interface-list=LAN
