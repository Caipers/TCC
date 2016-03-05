#!/usr/bin/python
# -*- coding: utf-8 -*- 

import pyshark
import node
import re 

# pyshark docs: https://github.com/KimiNewt/pysharkty


######## TODO ############################
# TOTAL OF PACKETS
# TOTAL, % OF EACH KIND OF NWK PACKETS
# 

# frame.time_epoch for TimeStamp.


# cmd.id == 0x01 -> Route Resquest
# got them by route ID

class capture():
    """
    Capture class is responsible for capturing all desarible packages and return a 
    dictionary of unique nodes.
    PS: So far, only nwk_layer's link status command package is considered in this class. 
    """

    def __init__(self):

        # CMD_IDs #
        # 0x01 -> Route request
        # 0x02 -> Route reply
        # 0x03 -> Network status
        # 0x04 -> Leave
        # 0x05 -> Route record
        # 0x06 -> Rejoin request
        # 0x07 -> Rejoin responde
        # 0x08 -> Link status
        # 0x09 -> Network report
        # 0x0a -> Network update

        # counters
        self.pkt_total               = 0
        self.nwk_cmd_pkt_total       = 0
        self.route_request_counter   = 0
        self.route_reply_counter     = 0
        self.nwk_status_counter      = 0
        self.leave_counter           = 0
        self.route_record_counter    = 0
        self.rejoin_request_counter  = 0
        self.rejoin_responde_counter = 0
        self.link_status_counter     = 0
        self.nwk_report_counter      = 0
        self.nwk_upd_counter         = 0
        self.reserved_counter        = 0

    def fileCapture(self, pcapFile):
        # When entering in this function, the import of node module disappers. 
        # I still do not know why.
        import node
        
        """
        Capture all nwk command packets. They belong to zbee_nwk Layer which 
        has zbee_nwk.cmd.id == 0x0[1-a] according to ZigBee Specification document
        """

        capture = pyshark.FileCapture(pcapFile, keep_packets = False)
        cap = capture.next()

        aux_node = None
        nodes = [] # list of nodes

        
        # trying to find a bug in the library on pyshark.
        try:
            while(cap is not None):
                try:
                    self.pkt_total += 1
                    cmd_id = self.convStrtoFF(cap.zbee_nwk.cmd_id)

                    # nwk commands between 0x0B to 0xFF are reserved
                    if (cmd_id != "0x01" and cmd_id != "0x02" and cmd_id != "0x03" and 
                        cmd_id != "0x04" and cmd_id != "0x05" and cmd_id != "0x06" and 
                        cmd_id != "0x07" and cmd_id != "0x08" and cmd_id != "0x09" and 
                        cmd_id != "0x0a"):
                        self.nwk_cmd_pkt_total += 1
                        self.reserved_counter += 1
                        cap = capture.next()
                        continue

                # exception for package that HAS NOT zbee_nwk layer
                except AttributeError:
                    cap = capture.next()
                    continue

                # recoding basic information
                macAdr = str(cap.zbee_nwk.src64)
                nwkAdr = str(self.convStrtoFFFF(cap.zbee_nwk.src))
                panAdr = str(self.convStrtoFFFF(cap.wpan.dst_pan))

                self.nwk_cmd_pkt_total += 1
                if (cmd_id == "0x01"):
                    self.route_request_counter += 1
                    # TODO

                elif (cmd_id == "0x02"):
                    self.route_reply_counter += 1
                    # TODO

                elif (cmd_id == "0x03"):
                    self.nwk_status_counter += 1
                    # TODO

                elif (cmd_id == "0x04"):
                    self.leave_counter += 1
                    # TODO

                elif (cmd_id == "0x05"):
                    self.route_record_counter += 1
                    # TODO

                elif (cmd_id == "0x06"):
                    self.rejoin_request_counter += 1
                    # TODO

                elif (cmd_id == "0x07"):
                    self.rejoin_responde_counter += 1
                    # TODO

                elif (cmd_id == "0x08"):
                    self.link_status_counter += 1

                    # regular expressions
                    r_nwkAdr     = re.compile("0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f]", re.IGNORECASE)
                    r_nei_cost   = re.compile("[01357]")

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

                        if (r_nwkAdr.match(nei_nwk) == None or len(nwkAdr) != 6):
                            raise ValueError('Invalid nwk_adr value')
                        if (r_nei_cost.match(nei_in) == None or len(nei_in) != 1):
                            raise ValueError('Invalid neo_in value')
                        if (r_nei_cost.match(nei_out) == None or len(nei_out) != 1):
                            raise ValueError('Invalid neo_out value')

                        neighbors.append({"nwkAdr" : nei_nwk, "in_cost" : int(nei_in), "out_cost" : int(nei_out)})

                    index = self.indexNode(nwkAdr, nodes)
                    if (index == -1): # node does not exist
                        aux_node = node.node(nwkAdr, macAdr, panAdr)
                        nodes.append(aux_node)
                    else: # node exists
                        aux_node = self.findNode(nwkAdr, nodes)
                        # if node changed its PAN or another radio gets a someone's nwkAdr, 
                        # it must reset all previous data e start again.

                        if ((aux_node.getPanAdr() != panAdr) or (aux_node.getMacAdr() != macAdr)):
                            aux_node.resetNode()
                            aux_node.setNwkAdr(nwkAdr)
                            aux_node.setMacAdr(macAdr)
                            aux_node.setPanAdr(panAdr)

                    aux_node.setCurNeighbors(neighbors)
                    aux_node.addNpPreNeighbors()

                elif (cmd_id == "0x09"):
                    self.nwk_report_counter += 1
                    # TODO

                elif (cmd_id == "0x0a"):
                    self.nwk_upd_counter += 1
                    # TODO
                    
                cap = capture.next()

        except AttributeError:
            print "*******BUG IN PYSHARK (AttributeError)*******"
            print str(aux_node)
        except StopIteration:
            print "******* (StopIteration) *******"
            print str(aux_node)


        # self.printCounters()
        capture.close()

        # processing historical nodes
        for node in nodes:
            node.processPreNeighbors()

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
            if (strVal.isdigit() == True):
                intVal = int(strVal)
                hexVal = hex(intVal)
            elif (strVal[0] == "0" and strVal[1] == "x"):
                hexVal = strVal
            else:
                return None
        except: 
            return None

        try:
            int(hexVal, 16)
        except ValueError:
            return None

        if (len(hexVal) == 3):
            return "0x0"+hexVal[2].lower()
        if (len(hexVal) == 4):
            return hexVal.lower()
        else:
            return None

    def convStrtoFFFF(self, strVal):
        """
        Convert a String with int content to a hex like 0xFFFF.
        Return: 0xffff string value if OK
                None otherwise
        """

        try:
            if (strVal.isdigit() == True):
                intVal = int(strVal)
                hexVal = hex(intVal)
            elif (strVal[0] == "0" and strVal[1] == "x"):
                hexVal = strVal
            else:
                return None
        except: 
            return None

        try:
            int(hexVal, 16)
        except ValueError:
            return None

        if (len(hexVal) == 3):
            return ("0x000"+hexVal[2]).lower()
        if (len(hexVal) == 4):
            return ("0x00"+hexVal[2]+hexVal[3]).lower()
        if (len(hexVal) == 5):
            return ("0x0"+hexVal[2]+hexVal[3]+hexVal[4]).lower()
        if (len(hexVal) == 6):
            return hexVal.lower()
        else:
            return None

    def printCounters(self):
        print "Route request packages =",       str(self.route_request_counter)
        print "Route reply packages =",         str(self.route_reply_counter)
        print "Network status packages =",      str(self.nwk_status_counter)
        print "Leave packages =",               str(self.leave_counter)
        print "Route record packages =",        str(self.route_record_counter)
        print "Rejoin request packages =",      str(self.rejoin_request_counter)
        print "Rejoin response packages =",     str(self.rejoin_responde_counter)
        print "Link Status packages =",         str(self.link_status_counter)
        print "Network report packages =",      str(self.nwk_report_counter)
        print "Network update packages =",      str(self.nwk_upd_counter)
        print "Reserved packages =",            str(self.reserved_counter)
        print "TOTAL OF NETWORK CMD PACKAGES",  str(self.nwk_cmd_pkt_total)
        print "TOTAL OF PACKAGES",              str(self.pkt_total)

    def getCounters(self):
        """
        Return a dictionary of totals, in this patter:
        "0x01" -> Route request
        "0x02" -> Route reply
        "0x03" -> Network status
        "0x04" -> Leave
        "0x05" -> Route record
        "0x06" -> Rejoin request
        "0x07" -> Rejoin responde
        "0x08" -> Link status
        "0x09" -> Network report
        "0x0a" -> Network update
        "0xff"
        "nwk_cmd_tot" -> Total of network cmd packages
        "tot" -> Total of packages
        """

        dic = {"0x01" : self.route_request_counter, "0x02" : self.route_reply_counter,
               "0x03" : self.nwk_status_counter, "0x04" : self.leave_counter, 
               "0x05" : self.route_record_counter, "0x06" : self.rejoin_request_counter,
               "0x07" : self.rejoin_responde_counter, "0x08" : self.link_status_counter,
               "0x09" : self.nwk_report_counter, "0x0a" : self.nwk_upd_counter,
               "0xff" : self.reserved_counter, "nwk_cmd_tot" : self.nwk_cmd_pkt_total,
               "tot"  :  self.pkt_total}

        return dic
