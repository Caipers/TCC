#!/usr/bin/python
# -*- coding: utf-8 -*- 

import csv
	
class geoPositioning:
	"""
	Class that imports the geo positioning CSV file of Smartgreen's equipments in São Lourenço Park.
	File columns expected:
	'Smartgreen Serial Number','MAC Address','Latitude','Longiture' 

	Return: A List of Dictiories which each dictionary has:
	SN Number = dict["sn"]
	MAC Adress = dict["mac"] 
	Latitude = dict["lat"]
	Longitude = dict["lon"]
	Format: 
		MAC: XX:XX:XX:XX:XX:XX:XX:XX
		Latitude and Longiture format is XX.XXXXXX
	"""

	def __init__(self, csvFilePath):
		self.ln = []
		csvFile = csv.reader(file(csvFilePath))
		for row in csvFile:
		   	dc = {}

			dc["sn"] = row[0]
			mac = row[1][0:2]+":"+row[1][2:4]+":"+row[1][4:6]+":"+row[1][6:8]+":"+row[1][8:10]+":"+row[1][10:12]+":"+row[1][12:14]+":"+row[1][14:16]
			mac = mac.lower()
			dc["mac"] = mac
			lat = row[2][0:3]+'.'+row[2][3:len(row[2])]
			dc["lat"] = lat
			lon = row[3][0:3]+'.'+row[3][3:len(row[3])]
			dc["lon"] = lon
			self.ln.append(dc)

	def getValues(self, mac):
		"""
		Return a dict containing SN Number, MAC Address, Latitude and Longiture values if MAC is found
		or None otherwise
		"""
		# print "MAC in getValues:",mac
		ln = self.ln
		for l in ln:
			# l is a dictionary
			if (l["mac"] == mac):
				return l

		return None

	def printList(self):
		print self.ln