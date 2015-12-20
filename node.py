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
            raise AttributeError('Incorrect nwkAdr')
        if (self.r_panAdr.match(panAdr) == None):
            raise AttributeError('Incorrect panAdr')
        if (self.r_macAdr.match(macAdr) == None):
            raise AttributeError('Incorrect macAdr')
        
        self.nwkAdr = nwkAdr
        self.macAdr = macAdr
        self.panAdr = panAdr
        self.neighbors = []

    def setnwkAdr(self, nwkAdr):
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
    def setNeighbors(self, neighbors):
        self.neighbors = neighbors

    def getnwkAdr(self):
        return self.nwkAdr
    def getMacAdr(self):
        return self.macAdr
    def getPanAdr(self):
        return self.panAdr
    def getNeighbors(self):
        return self.neighbors