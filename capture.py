#!/usr/bin/python
# -*- coding: utf-8 -*- 

# pyshark docs: https://github.com/KimiNewt/pysharkty
import pyshark
import node
import re
import json
import time

class capture():
    """
    Capture class is responsible for capturing all desarible packages and return a 
    dictionary of unique nodes.
    So far, Route Request (0x01), Route Reply (0x02) and Link Status (0x08) command package are considered in this class. 
    """

    def __init__(self):
        # self.DEBUG_MODE = 0
        self.DEBUG_MODE = 1

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

        # counters of all packages
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

        # counters of processed packages
        self.p_pkt_total               = 0
        self.p_route_request_counter   = 0
        self.p_route_reply_counter     = 0
        self.p_nwk_status_counter      = 0
        self.p_leave_counter           = 0
        self.p_route_record_counter    = 0
        self.p_rejoin_request_counter  = 0
        self.p_rejoin_responde_counter = 0
        self.p_link_status_counter     = 0
        self.p_nwk_report_counter      = 0
        self.p_nwk_upd_counter         = 0
        self.p_reserved_counter        = 0

        # list of Route ID for Route Request packets
        self.requestRouteID = []
        # list of Route ID for Route Reply packets
        self.routeReplyID = []

    def fileCapture(self, pcapFile):
        # When entering in this function, the import of node module disappers. 
        # I still do not know why.
        import node
        
        """
        Capture all nwk command packets. They belong to zbee_nwk Layer which 
        has zbee_nwk.cmd.id == 0x0[1-a] according to ZigBee Specification document
        """
        print "Starting reading of a captured file... "

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

                self.nwk_cmd_pkt_total += 1

                # recoding basic information
                macAdr = str(cap.zbee_nwk.src64)
                nwkAdr = str(self.convStrtoFFFF(cap.zbee_nwk.src))
                panAdr = str(self.convStrtoFFFF(cap.wpan.dst_pan))

                # finds a node if exists, or create a new node, or reset a node if node changes its PAN.
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

                #################################################################################
                # Route Request
                if (cmd_id == "0x01"):
                    self.route_request_counter += 1
                    
                    # parsing request RouteID
                    tmp = str(cap.zbee_nwk)
                    cmd = "Route ID:"
                    start = tmp.find(cmd) + len(cmd) + 1
                    end = start + 5 # until 5 caracteres
                    rID = tmp[start:end].splitlines()[0] # gets until finds the first new line caracter.

                    # parsing destination
                    # must be the fourth "Destination:" of the string
                    cmd = "Destination:"
                    fst_start = tmp.find(cmd) + len(cmd) + 1
                    snd_start = tmp.find(cmd, fst_start) + len(cmd) + 1
                    thd_start = tmp.find(cmd, snd_start) + len(cmd) + 1
                    start = tmp.find(cmd, thd_start) + len(cmd) + 1
                    end = start + 6
                    dstAdr = tmp[start:end]

                    if (self.requestRouteID.__contains__(rID) == False):
                        self.p_route_request_counter += 1
                        self.p_pkt_total += 1

                        self.requestRouteID.append(rID)
                        aux_node.addRouteRequest(str(dstAdr))

                #################################################################################
                # Route Reply
                elif (cmd_id == "0x02"):
                    self.route_reply_counter += 1
                    
                    # parsing reply RouteID
                    tmp = str(cap.zbee_nwk)
                    cmd = "Route ID:"
                    start = tmp.find(cmd) + len(cmd) + 1
                    end = start + 5 # until 5 caracteres
                    rID = tmp[start:end].splitlines()[0] # gets until finds the first new line caracter.

                    # parsing originator
                    cmd = "Originator:"
                    start = tmp.find(cmd) + len(cmd) + 1
                    end = start + 6
                    oriAdr = tmp[start:end]
                    # print "oriAdr =", str(oriAdr)

                    # parsing responder
                    # must be the second "Responder:" of the string
                    cmd = "Responder:"
                    fst_start = tmp.find(cmd) + len(cmd) + 1
                    snd_start = tmp.find(cmd, fst_start) + len(cmd) + 1
                    start = tmp.find(cmd, snd_start) + len(cmd) + 1
                    end = start + 6
                    resAdr = tmp[start:end]

                    # parsing extended originator
                    # must be the second "Extended Originator:" and after a "(" of the string
                    cmd = "Extended Originator:"
                    fst_start = tmp.find(cmd) + len(cmd) + 1
                    snd_start = tmp.find(cmd, fst_start) + len(cmd) + 1
                    start = tmp.find("(", snd_start) + 1
                    end = start + 23
                    extOriAdr = tmp[start:end]

                    # parsing extended responder
                    # must be the second "Extended Responder:" and after a "(" of the string
                    cmd = "Extended Responder:"
                    fst_start = tmp.find(cmd) + len(cmd) + 1
                    snd_start = tmp.find(cmd, fst_start) + len(cmd) + 1
                    start = tmp.find("(", snd_start) + 1
                    end = start + 23
                    extResAdr = tmp[start:end]

                    ###################################################################
                    # WARNING: For Route Reply, usually the originator and responder
                    # are not srcAdr nor dstAdr, and is necessary to check if the 
                    # responder is already created. The responder is the generetor of
                    # this command, so its resAdr is used as nwkAdr of the node.
                    ###################################################################

                    #finds a node if exists, or create a new node, or reset a node if node changes its PAN.
                    index = self.indexNode(resAdr, nodes)
                    if (index == -1): # node does not exist
                        aux_node = node.node(resAdr, extResAdr, panAdr)
                        nodes.append(aux_node)
                    else: # node exists
                        aux_node = self.findNode(resAdr, nodes)
                        # if node changed its PAN or another radio gets a someone's resAdr, 
                        # it must reset all previous data e start again.

                        if ((aux_node.getPanAdr() != panAdr) or (aux_node.getMacAdr() != extResAdr)):
                            aux_node.resetNode()
                            aux_node.setNwkAdr(resAdr)
                            aux_node.setMacAdr(extResAdr)
                            aux_node.setPanAdr(panAdr)

                    if (self.routeReplyID.__contains__(rID) == False):
                        self.p_route_reply_counter += 1
                        self.p_pkt_total += 1

                        self.routeReplyID.append(rID)
                        aux_node.addRouteReply(str(oriAdr))

                #################################################################################
                # Network status
                # Not implemented because lack of packets for testing.
                elif (cmd_id == "0x03"):
                    self.nwk_status_counter += 1
                    # TODO

                #################################################################################
                # Leave
                # Not implemented because lack of packets for testing.
                elif (cmd_id == "0x04"):
                    self.leave_counter += 1
                    # TODO

                #################################################################################
                # Route record:
                # The route record command allows the route taken by a unicast packet through the
                # network to be recorded in the command payload and delivered to the destination
                # device.
                # The destination will know the complete path when the packet arrives from the
                # source. So it records in the destination node the path from the source. For
                # each complete route path for the destination, it appends a list.
                elif (cmd_id == "0x05"):
                    self.route_record_counter += 1
                    relayList = []

                    dstAdr = str(self.convStrtoFFFF(cap.zbee_nwk.dst))
                    srcAdr = str(self.convStrtoFFFF(cap.zbee_nwk.src))
                    wpanDstAdr = str(self.convStrtoFFFF(cap.wpan.dst16))

                    # only process a packet if the destination of the packets is the same
                    # of the destination of the message.
                    if (str(wpanDstAdr) == dstAdr):
                        self.p_route_record_counter += 1

                        tmp = str(cap.zbee_nwk)

                        # parsing MAC of destination
                        cmd = "Destination:"
                        fst_start = tmp.find(cmd) + len(cmd) + 1
                        start = tmp.find("(", fst_start) + 1
                        end = start + 23
                        macAdr = tmp[start:end]

                        # parsing relay count
                        cmd = "Relay Count:"
                        start = tmp.find(cmd) + len(cmd) + 1
                        end = start + 2
                        relayCount = int(tmp[start:end].splitlines()[0]) # gets until finds the first new line caracter.

                        # parsing relay devices 
                        for i in range(1, relayCount + 1):
                            cmd = "Relay Device "+str(i)+":"
                            start = tmp.find(cmd) + len(cmd) + 1
                            end = start + 6
                            relayList.append(tmp[start:end])

                        ######################################################################################
                        # In Route Record, the processing node is not srcAdr, instead is when 
                        # wpan.dst16 == zbee_nwk.dst so it's necessary to find it.
                        ######################################################################################

                        # finds a node if exists, or create a new node, or reset a node if node changes its PAN.
                        index = self.indexNode(dstAdr, nodes)
                        if (index == -1): # node does not exist
                            aux_node = node.node(dstAdr, macAdr, panAdr)
                            nodes.append(aux_node)
                        else: # node exists
                            aux_node = self.findNode(dstAdr, nodes)
                            # if node changed its PAN or another radio gets a someone's nwkAdr, 
                            # it must reset all previous data e start again.

                            if ((aux_node.getPanAdr() != panAdr) or (aux_node.getMacAdr() != macAdr)):
                                aux_node.resetNode()
                                aux_node.setNwkAdr(dstAdr)
                                aux_node.setMacAdr(macAdr)
                                aux_node.setPanAdr(panAdr)

                        aux_node.addRouteRecord(srcAdr, relayCount, relayList)


                #################################################################################
                # Rejoin responde
                # Not implemented because lack of packets for testing.
                elif (cmd_id == "0x06"):
                    self.rejoin_request_counter += 1
                    # TODO

                # Rejoin request
                # Not implemented because lack of packets for testing.
                #################################################################################
                elif (cmd_id == "0x07"):
                    self.rejoin_responde_counter += 1
                    # TODO

                #################################################################################
                # Link Status
                elif (cmd_id == "0x08"):
                    self.link_status_counter += 1
                    self.p_link_status_counter += 1
                    self.p_pkt_total += 1

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

                    aux_node.setCurNeighbors(neighbors)
                    aux_node.addNpPreNeighbors()

                #################################################################################
                # Not implemented because lack of packets for testing.
                # Network report
                elif (cmd_id == "0x09"):
                    self.nwk_report_counter += 1
                    # TODO

                #################################################################################
                # Network update
                # Not implemented because lack of packets for testing.
                elif (cmd_id == "0x0a"):
                    self.nwk_upd_counter += 1
                    # TODO
                
                cap = capture.next()

        except AttributeError:
            print "*******BUG IN PYSHARK (AttributeError)*******"
            print self.printCounters()
        except StopIteration:
            print "Reading has finished"

        capture.close()

        # processing historical nodes
        output = "**BEGIN**"
        for node in nodes:
            node.processPreNeighbors()
            output += node.saveHistoricalNeighbors()
        output += "**END**"
        print "output:"
        print output

        if (self.DEBUG_MODE == 1):
            # print requestRouteID
            print "requestRouteID List:"
            print str(self.requestRouteID)
            print ""

            # print replyResquestID
            print "replyResquestID List:"
            print str(self.routeReplyID)
            print ""

            # print totals
            print "Printing Counters:"
            self.printCounters()
            print ""

            # print processed totals
            print "Printing Processed Counters:"
            self.printPCounters()
            print ""

        return nodes

    def pseudoLiveCapture(self, pcapFile, periodRefresh = 15):
        """
        Pseudo-Live Capture capturing
        Save in a file 
        """
        import node

        nodes = [] # list of nodes
        filePath = "/home/samuel/TCC/logs/pseudoLiveCaptureOutput.log"

        pktCounter = 0
        print "Starting..."

        # waiting first packet
        print "Waiting first packet"
        while True:
            try: 
                capture = pyshark.FileCapture(pcapFile)
                cap = capture[pktCounter]
                pktCounter += 1
                print "pktCounter="+str(pktCounter)
                capture.close()
                break
            except KeyError:
                print "Waiting for the first packet"
                time.sleep(15)

        print "First packet has arrived"
        f = file(filePath, "w")

        while True:
            # f.truncate(0)
            # output = "**BEGIN**\n"
            # print "Outter while"
            capture = pyshark.FileCapture(pcapFile)

            while True:
                # print "Inner while"
                aux_node = None
                try:
                    # cap = capture[pktCounter]
                    # pktCounter += 1
                    # print "pktCounter="+str(pktCounter)
            
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

                                # just testing, remove after.
                                # if (pktCounter % 25 == 0):
                                #     raise StopIteration("Testing")

                                cap = capture[pktCounter]
                                pktCounter += 1
                                print "Not a valid command...",
                                print "pktCounter="+str(pktCounter)
                                continue

                        # exception for package that HAS NOT zbee_nwk layer
                        except AttributeError:
                            cap = capture[pktCounter]
                            pktCounter += 1
                            print "It has not a zbee_nwk layer...",
                            print "pktCounter="+str(pktCounter)
                            continue

                        self.nwk_cmd_pkt_total += 1

                        # recoding basic information
                        macAdr = str(cap.zbee_nwk.src64)
                        nwkAdr = str(self.convStrtoFFFF(cap.zbee_nwk.src))
                        panAdr = str(self.convStrtoFFFF(cap.wpan.dst_pan))

                        # finds a node if exists, or create a new node, or reset a node if node changes its PAN.
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

                        #################################################################################
                        # Route Request
                        if (cmd_id == "0x01"):
                            self.route_request_counter += 1
                            
                            # parsing request RouteID
                            tmp = str(cap.zbee_nwk)
                            cmd = "Route ID:"
                            start = tmp.find(cmd) + len(cmd) + 1
                            end = start + 5 # until 5 caracteres
                            rID = tmp[start:end].splitlines()[0] # gets until finds the first new line caracter.

                            # parsing destination
                            # must be the fourth "Destination:" of the string
                            cmd = "Destination:"
                            fst_start = tmp.find(cmd) + len(cmd) + 1
                            snd_start = tmp.find(cmd, fst_start) + len(cmd) + 1
                            thd_start = tmp.find(cmd, snd_start) + len(cmd) + 1
                            start = tmp.find(cmd, thd_start) + len(cmd) + 1
                            end = start + 6
                            dstAdr = tmp[start:end]

                            if (self.requestRouteID.__contains__(rID) == False):
                                self.p_route_request_counter += 1
                                self.p_pkt_total += 1

                                self.requestRouteID.append(rID)
                                aux_node.addRouteRequest(str(dstAdr))

                        #################################################################################
                        # Route Reply
                        elif (cmd_id == "0x02"):
                            self.route_reply_counter += 1
                            
                            # parsing reply RouteID
                            tmp = str(cap.zbee_nwk)
                            cmd = "Route ID:"
                            start = tmp.find(cmd) + len(cmd) + 1
                            end = start + 5 # until 5 caracteres
                            rID = tmp[start:end].splitlines()[0] # gets until finds the first new line caracter.

                            # parsing originator
                            cmd = "Originator:"
                            start = tmp.find(cmd) + len(cmd) + 1
                            end = start + 6
                            oriAdr = tmp[start:end]
                            # print "oriAdr =", str(oriAdr)

                            # parsing responder
                            # must be the second "Responder:" of the string
                            cmd = "Responder:"
                            fst_start = tmp.find(cmd) + len(cmd) + 1
                            snd_start = tmp.find(cmd, fst_start) + len(cmd) + 1
                            start = tmp.find(cmd, snd_start) + len(cmd) + 1
                            end = start + 6
                            resAdr = tmp[start:end]

                            # parsing extended originator
                            # must be the second "Extended Originator:" and after a "(" of the string
                            cmd = "Extended Originator:"
                            fst_start = tmp.find(cmd) + len(cmd) + 1
                            snd_start = tmp.find(cmd, fst_start) + len(cmd) + 1
                            start = tmp.find("(", snd_start) + 1
                            end = start + 23
                            extOriAdr = tmp[start:end]

                            # parsing extended responder
                            # must be the second "Extended Responder:" and after a "(" of the string
                            cmd = "Extended Responder:"
                            fst_start = tmp.find(cmd) + len(cmd) + 1
                            snd_start = tmp.find(cmd, fst_start) + len(cmd) + 1
                            start = tmp.find("(", snd_start) + 1
                            end = start + 23
                            extResAdr = tmp[start:end]

                            ###################################################################
                            # WARNING: For Route Reply, usually the originator and responder
                            # are not srcAdr nor dstAdr, and is necessary to check if the 
                            # responder is already created. The responder is the generetor of
                            # this command, so its resAdr is used as nwkAdr of the node.
                            ###################################################################

                            #finds a node if exists, or create a new node, or reset a node if node changes its PAN.
                            index = self.indexNode(resAdr, nodes)
                            if (index == -1): # node does not exist
                                aux_node = node.node(resAdr, extResAdr, panAdr)
                                nodes.append(aux_node)
                            else: # node exists
                                aux_node = self.findNode(resAdr, nodes)
                                # if node changed its PAN or another radio gets a someone's resAdr, 
                                # it must reset all previous data e start again.

                                if ((aux_node.getPanAdr() != panAdr) or (aux_node.getMacAdr() != extResAdr)):
                                    aux_node.resetNode()
                                    aux_node.setNwkAdr(resAdr)
                                    aux_node.setMacAdr(extResAdr)
                                    aux_node.setPanAdr(panAdr)

                            if (self.routeReplyID.__contains__(rID) == False):
                                self.p_route_reply_counter += 1
                                self.p_pkt_total += 1

                                self.routeReplyID.append(rID)
                                aux_node.addRouteReply(str(oriAdr))

                        #################################################################################
                        # Network status
                        # Not implemented because lack of packets for testing.
                        elif (cmd_id == "0x03"):
                            self.nwk_status_counter += 1
                            # TODO

                        #################################################################################
                        # Leave
                        # Not implemented because lack of packets for testing.
                        elif (cmd_id == "0x04"):
                            self.leave_counter += 1
                            # TODO

                        #################################################################################
                        # Route record:
                        # The route record command allows the route taken by a unicast packet through the
                        # network to be recorded in the command payload and delivered to the destination
                        # device.
                        # The destination will know the complete path when the packet arrives from the
                        # source. So it records in the destination node the path from the source. For
                        # each complete route path for the destination, it appends a list.
                        elif (cmd_id == "0x05"):
                            self.route_record_counter += 1
                            relayList = []

                            dstAdr = str(self.convStrtoFFFF(cap.zbee_nwk.dst))
                            srcAdr = str(self.convStrtoFFFF(cap.zbee_nwk.src))
                            wpanDstAdr = str(self.convStrtoFFFF(cap.wpan.dst16))

                            # only process a packet if the destination of the packets is the same
                            # of the destination of the message.
                            if (str(wpanDstAdr) == dstAdr):
                                self.p_route_record_counter += 1

                                tmp = str(cap.zbee_nwk)

                                # parsing MAC of destination
                                cmd = "Destination:"
                                fst_start = tmp.find(cmd) + len(cmd) + 1
                                start = tmp.find("(", fst_start) + 1
                                end = start + 23
                                macAdr = tmp[start:end]

                                # parsing relay count
                                cmd = "Relay Count:"
                                start = tmp.find(cmd) + len(cmd) + 1
                                end = start + 2
                                relayCount = int(tmp[start:end].splitlines()[0]) # gets until finds the first new line caracter.

                                # parsing relay devices 
                                for i in range(1, relayCount + 1):
                                    cmd = "Relay Device "+str(i)+":"
                                    start = tmp.find(cmd) + len(cmd) + 1
                                    end = start + 6
                                    relayList.append(tmp[start:end])

                                ######################################################################################
                                # In Route Record, the processing node is not srcAdr, instead is when 
                                # wpan.dst16 == zbee_nwk.dst so it's necessary to find it.
                                ######################################################################################

                                # finds a node if exists, or create a new node, or reset a node if node changes its PAN.
                                index = self.indexNode(dstAdr, nodes)
                                if (index == -1): # node does not exist
                                    aux_node = node.node(dstAdr, macAdr, panAdr)
                                    nodes.append(aux_node)
                                else: # node exists
                                    aux_node = self.findNode(dstAdr, nodes)
                                    # if node changed its PAN or another radio gets a someone's nwkAdr, 
                                    # it must reset all previous data e start again.

                                    if ((aux_node.getPanAdr() != panAdr) or (aux_node.getMacAdr() != macAdr)):
                                        aux_node.resetNode()
                                        aux_node.setNwkAdr(dstAdr)
                                        aux_node.setMacAdr(macAdr)
                                        aux_node.setPanAdr(panAdr)

                                aux_node.addRouteRecord(srcAdr, relayCount, relayList)


                        #################################################################################
                        # Rejoin responde
                        # Not implemented because lack of packets for testing.
                        elif (cmd_id == "0x06"):
                            self.rejoin_request_counter += 1
                            # TODO

                        # Rejoin request
                        # Not implemented because lack of packets for testing.
                        #################################################################################
                        elif (cmd_id == "0x07"):
                            self.rejoin_responde_counter += 1
                            # TODO

                        #################################################################################
                        # Link Status
                        elif (cmd_id == "0x08"):
                            self.link_status_counter += 1
                            self.p_link_status_counter += 1
                            self.p_pkt_total += 1

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

                            aux_node.setCurNeighbors(neighbors)
                            aux_node.addNpPreNeighbors()
                            # aux_node.processPreNeighbors()

                        #################################################################################
                        # Not implemented because lack of packets for testing.
                        # Network report
                        elif (cmd_id == "0x09"):
                            self.nwk_report_counter += 1
                            # TODO

                        #################################################################################
                        # Network update
                        # Not implemented because lack of packets for testing.
                        elif (cmd_id == "0x0a"):
                            self.nwk_upd_counter += 1
                            # TODO
                        
                        cap = capture[pktCounter]
                        pktCounter += 1
                        print "pktCounter="+str(pktCounter)

                except AttributeError:
                    print "*******BUG IN PYSHARK (AttributeError)*******"
                    print self.printCounters()
                    break
                except StopIteration:
                    print "*******StopIteration*******"
                    # processing historical nodes
                    f.truncate(0)
                    output = "**BEGIN**\n"
                    for node in nodes:
                        totin, totout = node.processPreNeighbors()
                        print "processPre in and out",totin, totout
                        output += node.saveHistoricalNeighbors()
                    output += "**END**\n"
                    f.write(output)
                    f.flush()
                    # f.close()
                    print "Reading has finished"
                    print "Waiting for more packets"
                    time.sleep(15)
                    break
                except KeyError:
                    print "*******KeyError*******"
                    f.seek(0)
                    f.truncate()
                    output = "**BEGIN**\n"
                    for node in nodes:
                        # print node.getNwkAdr()
                        totin, totout = node.processPreNeighbors()
                        # print "processPre in and out",totin, totout
                        output += node.saveHistoricalNeighbors()
                    output += "**END**\n"
                    print "output"
                    print str(output)
                    print "len output = ",len(output)
                    f.write(output)
                    f.flush()
                    # f.close()
                    print "KeyError has occured"
                    print "Waiting for more packets"
                    time.sleep(15)
                    break

            print "Restarting..."

            capture.close()


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

    def printPCounters(self):
        print "Processed Route request packages =",       str(self.p_route_request_counter)
        print "Processed Route reply packages =",         str(self.p_route_reply_counter)
        print "Processed Network status packages =",      str(self.p_nwk_status_counter)
        print "Processed Leave packages =",               str(self.p_leave_counter)
        print "Processed Route record packages =",        str(self.p_route_record_counter)
        print "Processed Rejoin request packages =",      str(self.p_rejoin_request_counter)
        print "Processed Rejoin response packages =",     str(self.p_rejoin_responde_counter)
        print "Processed Link Status packages =",         str(self.p_link_status_counter)
        print "Processed Network report packages =",      str(self.p_nwk_report_counter)
        print "Processed Network update packages =",      str(self.p_nwk_upd_counter)
        print "Processed Reserved packages =",            str(self.p_reserved_counter)
        print "TOTAL OF PROCESSED PACKAGES =",            str(self.p_pkt_total)

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
        "0xff" -> Reserved
        "nwk_cmd_tot" -> Total of network cmd packages
        "tot" -> Total of packages
        """

        dic = {"0x01" : self.route_request_counter,     "0x02"        : self.route_reply_counter,
               "0x03" : self.nwk_status_counter,        "0x04"        : self.leave_counter, 
               "0x05" : self.route_record_counter,      "0x06"        : self.rejoin_request_counter,
               "0x07" : self.rejoin_responde_counter,   "0x08"        : self.link_status_counter,
               "0x09" : self.nwk_report_counter,        "0x0a"        : self.nwk_upd_counter,
               "0xff" : self.reserved_counter,          "nwk_cmd_tot" : self.nwk_cmd_pkt_total,
               "tot"  : self.pkt_total}

        return dic

    def getPCounters(self):
        """
        Return a dictionary of total of processed, in this patter:
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
        "0xff" -> Reserved
        "tot" -> Total of packages
        """

        dic = {"0x01" : self.p_route_request_counter,   "0x02" : self.p_route_reply_counter,
               "0x03" : self.p_nwk_status_counter,      "0x04" : self.p_leave_counter, 
               "0x05" : self.p_route_record_counter,    "0x06" : self.p_rejoin_request_counter,
               "0x07" : self.p_rejoin_responde_counter, "0x08" : self.p_link_status_counter,
               "0x09" : self.p_nwk_report_counter,      "0x0a" : self.p_nwk_upd_counter,
               "0xff" : self.p_reserved_counter,        "tot"  : self.p_pkt_total}

        return dic

    def getJSONCounters(self):
        return json.dumps(self.getCounters())

    def getJSONPCounters(self):
        return json.dumps(self.getPCounters())