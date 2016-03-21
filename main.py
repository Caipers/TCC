#!/usr/bin/python
# -*- coding: utf-8 -*- 

# ******************************************************************************************
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
# ******************************************************************************************

import pyshark
import capture
import json
import lib.geoPositioning

# PCAP_FILE = 'pcap_files/bigger_file.PCAP'
# PCAP_FILE = 'pcap_files/smaller_file.PCAP'
# PCAP_FILE = 'pcap_files/entire_park_05_03.PCAP'
PCAP_FILE = '/home/samuel/Downloads/telit-sniffer/bin/capture.pcap'

cap = capture.capture()
# nodes = cap.fileCapture(PCAP_FILE)
cap.pseudoLiveCapture(PCAP_FILE)



# print "Capture JSONs"
# print str(cap.getJSONCounters())
# print str(cap.getJSONPCounters())

# f = "/home/samuel/TCC/docs/geo_positions.csv"

# tot_pkt = 0
# geo = lib.geoPositioning.geoPositioning(f)


# print "Processing nodes..."
# for node in nodes:
#     """Node is a node object"""

#     values = geo.getValues(node.getMacAdr())
#     if (values == None):
#         # print "The Location of node",node.getMacAdr(),"has not been found"
#         pass
#     else:
#         node.setLocation(values["lat"], values["lon"])
#         node.setSN(values["sn"])

    
#     tot_pkt += node.getPacketTotal()

#     # print str(json.loads(node.getJSONRouteRequest()))
#     # print str(json.loads(node.getJSONRouteRecord()))
#     print str(json.loads(node.getJSONRouteReply()))
    

#     # # route record
#     # rrc, rrl = node.getRouteRecord()
#     # if (rrc != 0):
#     #     print node.getNwkAdr()+"s packet counter:", rrc
#     #     print str(rrl)

#     # route request counter 
#     # rrc, rrl = node.getRouteRequest()
#     # if (node.getNwkAdr() == "0x0000"):
#     #     print "Node",node.getNwkAdr(),"route requested",str(rrc),"times"
#     #     print "Destinations:"
#     #     print str(rrl)
#     print 

#     # if (cap.DEBUG_MODE == 1):
#     #     rrc, rrl = node.getRouteReply()
#     #     print "Node",node.getNwkAdr(),"reply requested",str(rrc),"times"
#     #     print "Destinations:"
#     #     print str(rrl)
        
#     # print "\t",node.getPacketTotal(),'packets of node =>',node.getNwkAdr(),node.getMacAdr()
#     # node.saveHistoricalNeighbors()

#     # print "Basics of", node.getNwkAdr(),str(node.getJSONBasics())
#     # print "Current neighbors",node.getJSONCurNeighbors()
    
#     # if node.isResetedNode() == True:
#     #     print "Node",node.getNwkAdr(),"is a reseted node"

#     # **************************************************
#     # tmp contais a 3D matrix (tmp[node][neighbors])
#     # EXAMPLES
#     # tmp[0] is the network address of this node
#     # tmp[1] is the node's historical neighbors
#     # tmp[1][0] is the first neighbor of the list of neighbors (a dictionary).
#     # tmp[1][0]['nkwAdr'] to access the network address of the first neighbor.
#     # ***************************************************

#     # if (cap.DEBUG_MODE == 1):
#     #     tmp = json.loads(node.getJSONHistoricalNeighbors())
#     #     print json.loads(node.getJSONHistoricalNeighbors())

# print "Processed"

# # if (cap.DEBUG_MODE == 1):
# #     print "Total of packets processed of capturing =", tot_pkt

