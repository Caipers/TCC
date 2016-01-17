#!/usr/bin/python
# -*- coding: utf-8 -*- 

import re

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
        
        if (self.r_nwkAdr.match(nwkAdr) == None):
            print str(nwkAdr)
            raise ValueError('Incorrect nwkAdr')
        if (self.r_panAdr.match(panAdr) == None):
            print str(panAdr)
            raise ValueError('Incorrect panAdr')
        if (self.r_macAdr.match(macAdr) == None):
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
        self.curNeighbors = [] # Current Neighbors
        self.npPreNeighbors = [] # Non-processed previous neighbors (List of Neighbors -> List of List of Dictionary)
        self.pPreNeighbors = [] # Non-processed previous neighbors (List of a Dictionary)
        self.ResetedNode = False

    def setNwkAdr(self, nwkAdr):
        if (self.r_nwkAdr.match(nwkAdr) == None):
            raise AttributeError('Incorrect nwkAdr')

        self.nwkAdr = nwkAdr
    def setMacAdr(self, macAdr):
        if (self.r_macAdr.match(macAdr) == None):
            raise AttributeError('Incorrect macAdr')

        self.macAdr = macAdr
    def setPanAdr(self, panAdr):
        if (self.r_panAdr.match(panAdr) == None):
            raise AttributeError('Incorrect panAdr')

        self.panAdr = panAdr

    def setCurNeighbors(self, neighbors):
        """Set current neighbors"""

        self.curNeighbors = neighbors
        self.packet_total += 1

    def addNpPreNeighbors(self):
        """
        Add to non-processed previous neighbors of the node.
        List of Neighbor which is a List of List of a Dictionary
        """

        self.npPreNeighbors.append(self.getCurNeighbors())

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
                    # print "Node = ", self.nwkAdr, " has not the neighbor ", nwkAdr
                    self.pPreNeighbors.append({'nwkAdr' : nwkAdr, 'tot_in_cost' : inCost, 'tot_out_cost' : outCost, 'tot_pkt' : 1})
                else:
                    index = self.indexNeighbor(nwkAdr,self.pPreNeighbors)
                    # print "Node = ", self.nwkAdr, " has the neighbor ", nwkAdr, "with the index", index
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
                # print "hasNeighbor has found the nwkAdr", nwkAdr, "dic=", dic['']
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

    def getNwkAdr(self):
        return self.nwkAdr
    def getMacAdr(self):
        return self.macAdr
    def getPanAdr(self):
        return self.panAdr
    def getCurNeighbors(self):
        return self.curNeighbors
    def getHistoricalNeighbors(self):
        return self.pPreNeighbors
    def getPacketTotal(self):
        return self.packet_total
    def isResetedNode(self):
        return self.ResetedNode
    def isCoordinator(self):
        return self.coordinator

    def saveHistoricalNeighbors(self):
        f = file('histnb.log','a')

        for dic in self.pPreNeighbors:
            f.writelines(self.nwkAdr+';'+dic['nwkAdr']+';'+str(dic['tot_in_cost'])+';'+str(dic['tot_out_cost'])+';'+str(dic['tot_pkt'])+'\n')

        f.close()

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