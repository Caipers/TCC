#!/usr/bin/python
# -*- coding: utf-8 -*- 

import pyshark
import node
import re 

# pyshark docs: https://github.com/KimiNewt/pysharkty

class capture():
    """
    Capture class is responsible for capturing all desarible packages and return a 
    dictionary of unique nodes.
    PS: So far, only nwk_layer's link status command package is considered in this class. 
    """

    def fileCapture(self, pcapFile):
        """Capture all Link Status packets. They belong to zbee_nwk Layer which 
        has zbee_nwk.cmd.id == 0x08 according to ZigBee Specification document"""

        capture = pyshark.FileCapture(pcapFile, keep_packets = False)

        f = file('aux.log','w') # for debugging reasons
        tmp_node = None
        nodes = [] # list of nodes
        i = 0
        link_counter = 0
        cap = capture.next()

        # print str(cap)

        r_nwkAdr = re.compile("0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f]", re.IGNORECASE)
        r_nei_cost = re.compile("[01357]")
        
        # trying to find a bug in the library on pyshark.
        try:
            while(cap is not None):
                try:
                    # test if the zbee_nwk package IS NOT Link Status
                    cmd_id = self.convStrtoFF(cap.zbee_nwk.cmd_id)
                    if (cmd_id == None):
                        print "cmd_id is None"
                    # cmd_id = hex(int(cap.zbee_nwk.cmd_id))
                    if (cmd_id != "0x08"):
                        cap = capture.next()
                        i += 1
                        continue

                    # exception for package that HAS NOT zbee_nwk layer
                except AttributeError:
                    cap = capture.next()
                    i += 1
                    continue

                link_counter += 1
                # print "Aqui porra!!!"

                # recoding basic information
                macAdr = str(cap.zbee_nwk.src64)
                nwkAdr = self.convStrtoFFFF(cap.zbee_nwk.src)
                panAdr = self.convStrtoFFFF(cap.wpan.dst_pan)

                # parsing neighbouring information
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

                    if (r_nwkAdr.match(nei_nwk) == None):
                        raise ValueError('Invalid nwk_adr value')
                    if (r_nei_cost.match(nei_in) == None):
                        raise ValueError('Invalid neo_in value')
                    if (r_nei_cost.match(nei_out) == None):
                        raise ValueError('Invalid neo_out value')

                    neighbors.append({"nwkAdr" : nei_nwk, "in_cost" : int(nei_in), "out_cost" : int(nei_out)})
                    f.writelines(nwkAdr+';'+macAdr+';'+panAdr+';'+str(nei_nwk)+';'+str(nei_in)+';'+str(nei_out)+'\n')

                
                index = self.indexNode(nwkAdr, nodes)
                if (index == -1): # node does not exist
                    tmp_node = node.node(nwkAdr, macAdr, panAdr)
                    nodes.append(tmp_node)
                else: # node exists
                    tmp_node = self.findNode(nwkAdr, nodes)
                    # if node changed its PAN or another radio gets a someone's nwkAdr, 
                    # it must reset all previous data e start again.

                    if ((tmp_node.getPanAdr() != panAdr) or (tmp_node.getMacAdr() != macAdr)):
                        tmp_node.resetNode()
                        tmp_node.setNwkAdr(nwkAdr)
                        tmp_node.setMacAdr(macAdr)
                        tmp_node.setPanAdr(panAdr)

                tmp_node.setCurNeighbors(neighbors)
                tmp_node.addNpPreNeighbors()
                cap = capture.next()

        except AttributeError:
            print "*******BUG IN PYSHARK (AttributeError)*******"
            print str(tmp_node)
        except StopIteration:
            print "*******BUG IN PYSHARK (StopIteration)*******"
            print str(tmp_node)


        print "Link Status packages are ", str(link_counter)
        print "NOT Link Status packages are ", str(i)
        print "TOTAL ", str(i + link_counter)

        f.close()
        capture.close()
        return nodes

    def indexNode(self, nwkAdr, listOfNodes):
        """
        Method to find a specific index of a nwkAdr in a list of nodes
        Return -> Value >= 0 if the nwkAdr is found in the list, -1 otherwise
        """
        
        i = 0
        for node in listOfNodes: # 
            if (node.getNwkAdr() == nwkAdr):
                return i

            i += 1

        return -1

    def findNode(self, nwkAdr, listOfNodes):
        """
        Method to find a specific node object of a nwkAdr in a list of nodes
        Return -> node object if the nwkAdr is found in the list, -1 otherwise
        """
        
        for node in listOfNodes: # 
            if (node.getNwkAdr() == nwkAdr):
                return node

        return -1

    def convStrtoFF(self, strVal):
        """
        Convert a String with int content to a hex like 0xFF.
        Return: 0xff string value if OK
                None otherwise
        """

        try:
            intVal = int(strVal)
        except ValueError:
            print "String is not a int with base 10"

        hexVal = hex(intVal)
        if (len(hexVal) == 3):
            return "0x0"+hexVal[2]
        if (len(hexVal) == 4):
            return hexVal
        else:
            return None

    def convStrtoFFFF(self, strVal):
        """
        Convert a String with int content to a hex like 0xFFFF.
        Return: 0xffff string value if OK
                None otherwise
        """

        try:
            intVal = int(strVal)
        except ValueError:
            print "String is not a int with base 10"

        hexVal = hex(intVal)
        if (len(hexVal) == 3):
            return "0x000"+hexVal[2]
        if (len(hexVal) == 4):
            return "0x00"+hexVal[2]+hexVal[3]
        if (len(hexVal) == 5):
            return "0x0"+hexVal[2]+hexVal[3]+hexVal[4]
        if (len(hexVal) == 6):
            return hexVal
        else:
            return None

