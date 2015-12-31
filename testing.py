import pyshark
import capture

#!/usr/bin/python
# -*- coding: utf-8 -*- 

# pyshark docs: https://github.com/KimiNewt/pysharkty
# cap = pyshark.FileCapture('pcap_files/bigger_file.PCAP')

# filter ZB NWK https://www.wireshark.org/docs/dfref/z/zbee_nwk.html
# filter WPAN https://www.wireshark.org/docs/dfref/w/wpan.html

#############################################################
# INFORMACAO IMPORTANTE
# DST    Descricao (Table 3.54)
# 0xfffc All routers and coordinator
# 0xfffb Low power routers only
# 0xfff8 - 0xfffa Reserved

# Many-to-one routing
# https://www.digi.com/wiki/developer/index.php/Large_ZigBee_Networks_and_Source_Routing

# RSSI: The received signal strength (energy) can be measured for each received packet. The
# measured signal energy is quantized to form the received signal strength indicator
# (RSSI). The RSSI and the time at which the packet was received (timestamp) are
# available to MAC, NWK, and APL layers for any type of analysis. For example, the
# simplest way to generate the link quality indicator (LQI) is to use the RSSI as an
# indication of link quality.

#############################################################
# TIPO DE PACOTES ZIGBEE 
# LINK STATUS -> NWK Command Frame (Frame Type = 0x01 ID: 0x08)

# 3.6.3.4 Link Status Messages
# Wireless links may be asymmetric, that is, they may work well in one direction
# but not the other. This can cause route replies to fail, since they travel backwards
# along the links discovered by the route request.
# For many-to-one routing and two-way route discovery (nwkSymLink = TRUE), it
# is a requirement to discover routes that are reliable in both directions. To
# accomplish this, routers exchange link cost measurements with their neighbors by
# periodically transmitting link status frames as a one-hop broadcast. The reverse
# link cost information is then used during route discovery to ensure that discovered
# routes use high-quality links in both directions.

# 3.6.3.4.1 Initiation of a Link Status Command Frame
# When joined to a network, a ZigBee router or coordinator shall periodically send a
# link status command every nwkLinkStatusPeriod seconds, as a one-hop broadcast
# without retries. It may be sent more frequently if desired. Random jitter should be
# added to avoid synchronization with other nodes. See sub-clause 3.4.8 for the link
# status command frame format.
# End devices do not send link status command frames.

# The link status command frame allows neighboring routers to communicate their
# incoming link costs to each other as described in sub-clause 3.6.3.4. Link status
# frames are transmitted as one-hop broadcasts without retries.
#

# Link status entries are sorted in ascending order by network address. If all router
# neighbors do not fit in a single frame, multiple frames are sent. When sending
# multiple frames, the last network address in the link status list for frame N is equal
# to the first network address in the link status list for frame N+1.

# Each link status entry contains the network address of a router neighbor, least
# significant octet first, followed by the link status octet. The incoming cost field
# contains the device s estimate of the link cost for the neighbor, which is a value
# between 1 and 7. The outgoing cost field contains the value of the outgoing cost
# field from the neighbor table.
# Em outras palavras, Incoming cost do vizinho para o SRC_ADDRESS. Outcoming e pego
# do routering table.

# OBS: Implica que o NWK_SRC tem como vizinhos todos esses nos.



#
# print "CAP0 Complete " + str(cap[0])
# print "CAP0 Wpan" + str(cap[0].wpan)
# print "CAP0 ZB_NWK" + str(cap[0].zbee_nwk)
# cap[0].zbee_nwk.field_names

# print "wpan.rssi = " + str(cap[0].wpan.rssi)
# print "zbee_nwk.src64 = " + str(cap[0].zbee_nwk.src64)
# print "zbee_nwk.src = " + str(cap[0].zbee_nwk.src)
# print "zbee_nwk.dst = " + str(cap[0].zbee_nwk.dst)
# print "zbee_nwk = " + str(cap[0].zbee_nwk)


# print "wpan.rssi = " + str(cap[1].wpan.rssi)
# print "wpan.rssi = " + str(cap[2].wpan.rssi)
# print "wpan.rssi = " + str(cap[3].wpan.rssi)
# print "wpan.rssi = " + str(cap[4].wpan.rssi)

PCAP_FILE = 'pcap_files/bigger_file.PCAP'
# PCAP_FILE = 'pcap_files/smaller_file.PCAP'

cap = capture.capture()
nodes = cap.fileCapture(PCAP_FILE)

# print "nodes:", str(nodes)

f = file('nodes.log', 'w')

tot_in = 0
tot_out = 0
tot_pkt = 0

print "Following nodes has been processed:"
for node in nodes:
    """Node is a node object"""
    # node.printCurNeighbors()
    # if (node.getNwkAdr() == '0xd7e7'):
    #     print str(node.npPreNeighbors)

    t_in, t_out = node.processPreNeighbors()
    tot_pkt += node.getPacketTotal()
    tot_in += t_in
    tot_out += t_out

    print "\t",node.getPacketTotal(),'packets of node =>',node.getNwkAdr(),node.getMacAdr()
    node.saveHistoricalNeighbors()

    if node.isResetedNode() == True:
        print "Node",node.getNwkAdr,"is a reseted node"

    # print str(node.getHistoricalNeighbors())
    # print ""
    # f.writelines('Total Link Status for node ' + str(node.getNwkAdr()) + ' is ' + str(node.getPacketTotal()) + '\n')


print "Total of cost of incoming cost of all nodes =", tot_in
print "Total of cost of outcoming cost of all nodes =", tot_out
print "Total of packets processed of capturing =", tot_pkt
