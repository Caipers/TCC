#!/usr/bin/python
# -*- coding: utf-8 -*- 

import pyshark
import node

# pyshark docs: https://github.com/KimiNewt/pysharkty

class capture():

    # def __init__(self):


    def fileCapture(self, pcapFile):
        cap = pyshark.FileCapture(pcapFile)


        # recoding basic information
        nwkAdr = cap[0].zbee_nwk.src
        macAdr = cap[0].zbee_nwk.src64
        panAdr = cap[0].wpan.dst_pan

        # recoding neighbouring information
        tmp = str(cap[0].zbee_nwk)
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
        print tmp_node.getNeighbors()



