#!/usr/bin/python
# -*- coding: utf-8 -*- 

import re
import json

class node():
    """Class that implements a Zigbee network node"""

    def __init__(self, nwkAdr, macAdr, panAdr):
        """
        Arguments:
            nwkAdr = 16-bits ZigBee Network Address
            macAdr = 64-bits 802.15.4 Mac Address
            panAdr = 16-bits Wireless PAN Network
            neighbors = List of Dictionaries including nwkAdr, incoming and outcoming costs of the node's neighbor
        """

        self.r_nwkAdr = re.compile("0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f]", re.IGNORECASE)
        self.r_panAdr = re.compile("0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f]", re.IGNORECASE)
        self.r_macAdr = re.compile("[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]", re.IGNORECASE)
        
        if (self.r_nwkAdr.match(nwkAdr) == None or len(nwkAdr) != 6):
            print str(nwkAdr)
            raise ValueError('Incorrect nwkAdr')
        if (self.r_panAdr.match(panAdr) == None or len(panAdr) != 6):
            print str(panAdr)
            raise ValueError('Incorrect panAdr')
        if (self.r_macAdr.match(macAdr) == None or len(macAdr) != 23):
            print str(macAdr)
            raise ValueError('Incorrect macAdr')
        
        self.nwkAdr = nwkAdr
        self.macAdr = macAdr
        self.panAdr = panAdr
        
        if (nwkAdr == "0x0000"):
            self.coordinator = True
        else:
            self.coordinator = False

        self.packet_total = 0
        self.sn = None
        self.latitude = None 
        self.longitude = None 
        self.curNeighbors = [] # Current Neighbors
        self.npPreNeighbors = [] # Non-processed previous neighbors (List of Neighbors -> List of List of Dictionary)
        self.pPreNeighbors = [] # processed previous neighbors (List of a Dictionary)
        self.ResetedNode = False

        # for route request command
        self.routeRequestCounter = 0
        self.routeRequestList = []

        # for reply request command
        self.routeReplyCounter = 0
        self.routeReplyList = []

    def addRouteRequest(self, dstAdr):
        """
        Count total of RouteRequest of this node and its destinations.
        """

        self.routeRequestCounter += 1
        self.packet_total += 1

        routeRequestList = self.routeRequestList
        for rr in routeRequestList:
            # rr is a dict -> key = dstAdr, value = counter
            if (rr.has_key(dstAdr) == True):
                rr[dstAdr] += 1
                return

        # if there is not a dstAdr in the list, so append it
        routeRequestList.append({dstAdr : 1})

    def addRouteReply(self, oriAdr):
        """
        Count total of RouteReply of this node and its originator.
        The responder is this node.
        """

        self.routeReplyCounter += 1
        self.packet_total += 1

        routeReplyList = self.routeReplyList
        for rr in routeReplyList:
            # rr is a dict -> key = oriAdr, value = counter
            if (rr.has_key(oriAdr) == True):
                rr[oriAdr] += 1
                return

        # if there is not a oriAdr in the list, so append it
        routeReplyList.append({oriAdr : 1})

    def addNpPreNeighbors(self):
        """
        Add to non-processed previous neighbors of the node.
        List of Neighbor which is a List of List of a Dictionary
        """

        self.npPreNeighbors.append(self.getCurNeighbors())


    def setNwkAdr(self, nwkAdr):
        if (self.r_nwkAdr.match(nwkAdr) == None or len(nwkAdr) != 6):
            raise ValueError('Incorrect nwkAdr')

        self.nwkAdr = nwkAdr
    def setMacAdr(self, macAdr):
        if (self.r_macAdr.match(macAdr) == None or len(macAdr) != 23):
            raise ValueError('Incorrect macAdr')

        self.macAdr = macAdr
    def setPanAdr(self, panAdr):
        if (self.r_panAdr.match(panAdr) == None or len(panAdr) != 6):
            raise ValueError('Incorrect panAdr')

        self.panAdr = panAdr

    def setLocation(self, latitude, longitude):
        """
        Return: 
            latitude, longitude : float type 
        """
        # for Brazilian location both values are negative.
        if (float(latitude) > 0 or float(longitude) > 0):
            raise ValueError('Latitude or Longitude are not less than 0')

        # http://stackoverflow.com/questions/11849636/maximum-lat-and-long-bounds-for-the-world-google-maps-api-latlngbounds
        if (float(latitude) < -85 or float(latitude) > 85):
            raise ValueError('Latitude has valid range of [-85,85]')
        if (float(longitude) < -180 or float(longitude) > 180):
            raise ValueError('Latitude has valid range of [-180,180]')

        self.latitude = float(latitude)
        self.longitude = float(longitude)

    def setSN(self, sn):
        """
        SN has 13 decimal digits
        Return:
            SN : int type
        """        
        if (len(sn) != 13):
            raise ValueError('Length of the SN is different of 13')

        if (sn.isdigit() == False):
            raise ValueError('SN is not a digit')

        self.sn = int(sn)

    def setCurNeighbors(self, neighbors):
        """Set current neighbors"""

        self.curNeighbors = neighbors
        self.packet_total += 1

    

    def processPreNeighbors(self):
        """
        Process non-processed previous neighbors to compute statistical data
        about historical neighbors of the node.
        This method gets the npPreNeighbors list

        Result: List of information about previous packets about neighbors (self.pPreNeighbors)
        """

        npNeighbors = self.npPreNeighbors

        total_in = 0
        total_out = 0

        for npList in npNeighbors:
            # npList is a List of Neighbors
            for np in npList:
                # np is a dictionary
                nwkAdr = np['nwkAdr']
                inCost = int(np['in_cost'])
                outCost = int(np['out_cost'])
                total_in += inCost
                total_out += outCost

                if (self.hasNeighbor(nwkAdr, self.pPreNeighbors) == False):
                    self.pPreNeighbors.append({'nwkAdr' : nwkAdr, 'tot_in_cost' : inCost, 'tot_out_cost' : outCost, 'tot_pkt' : 1})
                else:
                    index = self.indexNeighbor(nwkAdr,self.pPreNeighbors)
                    dic = self.pPreNeighbors[index]

                    tot_in_cost = dic['tot_in_cost'] + inCost
                    tot_out_cost = dic['tot_out_cost'] + outCost
                    tot_pkt = dic['tot_pkt'] + 1

                    self.pPreNeighbors[index] = {'nwkAdr' : nwkAdr, 'tot_in_cost' : int(tot_in_cost), 'tot_out_cost' : int(tot_out_cost), 'tot_pkt' : int(tot_pkt)}

        self.npPreNeighbors = []

        return total_in, total_out

    def hasNeighbor(self, nwkAdr, listOfDict):
        """
        Method to discovery if a specific nwkAdr is in a list of a dictionary
        Return -> True if it is found, False otherwise
        """

        for dic in listOfDict: # dic is a dictionary
            if (dic['nwkAdr'] == nwkAdr):
                return True

        return False

    def indexNeighbor(self, nwkAdr, listOfDict):
        """
        Method to find a specific index of a nwkAdr in a list of a dictionary
        Return -> Value > 0 if the nwkAdr is found in the list, -1 otherwise
        """
        
        i = 0
        for dic in listOfDict: # dic is a dictionary
            if (dic['nwkAdr'] == nwkAdr):
                return i

            i += 1

        return -1

    def isResetedNode(self):
        return self.ResetedNode
    def isCoordinator(self):
        return self.coordinator

    def printCurNeighbors(self):
        """Print current neighbors in stdout"""

        neighbors = self.getCurNeighbors()

        print "###############################################################"
        print "Neighbors of", str(self.getNwkAdr()), "->", str(self.getMacAdr())
        print "panID", str(self.getPanAdr())
        print "###############################################################"
        print '{:<2}'.format("Num"), '{:<10}'.format("Neighbor"), '{:<3}'.format("in"), '{:<3}'.format("out")
        k = 1
        for neighbor in neighbors:
            print '{:<3}'.format('#' + str(k)), '{:<10}'.format(neighbor['nwkAdr']), '{:<3}'.format(neighbor['in_cost']), '{:<3}'.format(neighbor['out_cost'])
            k += 1

    
    def resetNode(self):
        """Clear all previuos data, lets node as new one. Set True in resetedNode"""

        self.nwkAdr = None
        self.macAdr = None
        self.panAdr = None
        self.packet_total = 0
        self.curNeighbors = []
        self.npPreNeighbors = [] 
        self.pPreNeighbors = []
        self.isResetedNode = True
        self.routeRequestCounter = 0
        self.routeRequestList = []

    def getNwkAdr(self):
        return self.nwkAdr
    def getMacAdr(self):
        return self.macAdr
    def getPanAdr(self):
        return self.panAdr
    def getLocation(self):
        return [self.latitude, self.longitude]
    def getSN(self):
        return self.sn
    def getCurNeighbors(self):
        return self.curNeighbors
    def getNpPreNeighbors(self):
        return self.npPreNeighbors
    def getHistoricalNeighbors(self):
        return self.pPreNeighbors
    def getPacketTotal(self):
        return self.packet_total
    def getRouteRequest(self):
        """
        Return total counter and a list of destinations and its counters.
        """

        return self.routeRequestCounter, self.routeRequestList
    def getRouteReply(self):
        """
        Return total counter and a list of originators and its counters.
        """

        return self.routeReplyCounter, self.routeReplyList
    def getJSONBasics(self):
        """
        Return basic information in JSON format about the node which is: nwkAdr, panAdr, macAdr, coordinator latitude
        longitude, serial number
        """
        return json.dumps([self.nwkAdr, self.panAdr, self.macAdr, self.coordinator, self.latitude, self.longitude, self.sn])
    def getJSONCurNeighbors(self):
        return json.dumps([self.nwkAdr, self.curNeighbors])
    def getJSONHistoricalNeighbors(self):
        """
        Returns:
            self.nwkAdr Network Address
            self.macAdr MAC Address
            self.packet_total Totals of link status packets this node had.
            self.latitude Latitude of the node
            self.longitude Longitude of the node
            self.pPreNeighbors Processed neighbors (List of dictionaries)
        """
        return json.dumps([self.nwkAdr, self.macAdr, self.packet_total, self.latitude, self.longitude, self.pPreNeighbors])
    
    def saveHistoricalNeighbors(self):
        f = file('histnb.log','a')

        for dic in self.pPreNeighbors:
            f.writelines(self.nwkAdr+';'+dic['nwkAdr']+';'+str(dic['tot_in_cost'])+';'+str(dic['tot_out_cost'])+';'+str(dic['tot_pkt'])+'\n')

        f.close()