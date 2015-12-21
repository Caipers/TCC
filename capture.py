#!/usr/bin/python
# -*- coding: utf-8 -*- 

import pyshark
import node
import time

# pyshark docs: https://github.com/KimiNewt/pysharkty

class capture():
    """
    Capture class is responsible for capturing all desarible packages and return a 
    dictionary of unique nodes.
    PS: So far, only nwk_layer's link status command package is considered in this class. 
    """

    def fileCapture(self, pcapFile):
        capture = pyshark.FileCapture(pcapFile)
        
        nodes = {}

        i = 0
        link_counter = 0

        # trying to find a bug in the library on pyshark.
        try:
            for cap in capture:
                try:
                    # test if the zbee_nwk package IS NOT Link Status
                    if (str(cap.zbee_nwk.cmd_id) != "0x08"):
                        # print str(i) + "The zbee_nwk package IS NOT a Link Status cmd"
                        i += 1
                        continue

                    # exception for package that HAS NOT zbee_nwk layer
                except AttributeError:
                    # print str(i) + " The package HAS NOT a zbee_nwk's layer "
                    i += 1
                    continue

                # i += 1
                link_counter += 1

                # recoding basic information
                nwkAdr = cap.zbee_nwk.src
                macAdr = cap.zbee_nwk.src64
                panAdr = cap.wpan.dst_pan

                # recoding neighbouring information
                tmp = str(cap.zbee_nwk)
                cmd = "Command Frame: Link Status"
                start = tmp.find(cmd) + len(cmd) + 1
                end = len(tmp)

                raw_neighbors = tmp[start:end]
                list_neighbors = raw_neighbors.splitlines()

                neighbors = []
                for neighbor in list_neighbors:
                    nei_nwk = neighbor[1:7]
                    nei_in = neighbor[24:25]
                    nei_out = neighbor[41:42]

                    neighbors.append({"nwkAdr" : nei_nwk, "in_cost" : nei_in, "out_cost" : nei_out})

                tmp_node = node.node(nwkAdr, macAdr, panAdr)
                tmp_node.setNeighbors(neighbors)

                nodes[nwkAdr] = {'node' : tmp_node}
                if (nwkAdr == "0x5b46"):
                    # print nwkAdr + " neighbors: " + str(neighbors)
                    print nodes[nwkAdr]

        except:
            print "*******BUG TO CORRECT*******"


        print "Link Status packages are ", str(link_counter)
        print "NOT Link Status packages are ", str(i)
        print "TOTAL ", str(i + link_counter)


        capture.close()
        return nodes