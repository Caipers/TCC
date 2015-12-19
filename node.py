#!/usr/bin/python
# -*- coding: utf-8 -*- 

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
        self.nwkAdr = nwkAdr
        self.macAdr = macAdr
        self.panAdr = panAdr
        self.neighbors = []

    def setnwkAdr(self, nwkAdr):
        self.nwkAdr = nwkAdr
    def setMacAdr(self, macAdr):
        self.macAdr = macAdr
    def setPanAdr(self, panAdr):
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