import pyshark


# pyshark docs: https://github.com/KimiNewt/pysharkty
cap = pyshark.FileCapture('bigger_file.PCAP')


# filter ZB NWK https://www.wireshark.org/docs/dfref/z/zbee_nwk.html
# filter WPAN https://www.wireshark.org/docs/dfref/w/wpan.html

# print cap[0]
# print cap[1]
# print cap[2]
# print cap[3]
print cap[4]
