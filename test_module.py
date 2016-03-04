# content of test_class.py
import pytest
import sys

from node import node

class TestClass:
	"""
	Unit test for capture and node classes
	"""
	def test_node_init(self):
		with pytest.raises(ValueError):
			# more len than expect
			node("0xfafa", "00:00:00:00:00:00:00:00ZZ", "0xffff")
			node("0xfafafa", "00:00:00:00:00:00:00:00", "0xffff")
			node("0xfafa", "00:00:00:00:00:00:00:00", "0xffffff")

			# invalid values with exact len
			node("0xzsdr", "00:00:00:00:00:00:00:00", "0xffff")
			node("0x1111", "XX:00:00:00:00:00:00:00", "0xffff")
			node("0x1111", "00:00:00:00:00:00:00:00", "0xzzzz")

			# invalid format
			node("1111", "00:00:00:00:00:00:00:00", "0x2222")
			node("0x1111", "00000000:00:00:00:00", "0x2222")
			node("0x1111", "00:00:00:00:00:00:00:00", "2222")

			# empty string
			node("","00:00:00:00:00:00:00:00", "0x2222")
			node("0xabcd","", "0x2222")
			node("0xabcd","00:00:00:00:00:00:00:00", "")


        # test coordinator
		n = node("0x0000", "FF:FF:00:00:00:00:00:00", "0x23bc")
		assert n.coordinator == 1
		n = node("0x0001", "FF:FF:00:00:00:00:00:00", "0x23bc")
		assert n.coordinator == 0

	def test_setNwkAdr(self):
		n = node("0xfaca", "00:00:00:00:00:00:00:00", "0xffff")
		with pytest.raises(ValueError):
			n.setNwkAdr("facaca")
			n.setNwkAdr("abcg")
			n.setNwkAdr("pp")
			n.setNwkAdr("")
			n.setNwkAdr("0xabcg")

		nwkAdr = "0xf1ca"
		n.setNwkAdr(nwkAdr)
		assert nwkAdr == n.getNwkAdr()

	def test_setPanAdr(self):
		n = node("0xfaca", "00:00:00:00:00:00:00:00", "0xffff")
		with pytest.raises(ValueError):
			n.setPanAdr("facaca")
			n.setPanAdr("abcg")
			n.setPanAdr("pp")
			n.setPanAdr("")
			n.setPanAdr("0xabcg")

		panAdr = "0xf1ca"
		n.setPanAdr(panAdr)
		assert panAdr == n.getPanAdr()

	def test_setMacAdr(self):
		n = node("0xfaca", "00:00:00:00:00:00:00:00", "0xffff")
		with pytest.raises(ValueError):
			n.setMacAdr("00:00:00:00:00:00:00:00:12")
			n.setMacAdr("00:00:00:00:00:00:00:00")
			n.setMacAdr("0000:00:00:00:00:00:00")
			n.setMacAdr("ZZ:GG:00:00:00:00:00:00")
			n.setMacAdr("")
			n.setMacAdr("0xZZ")

		macAdr = "00:0d:6f:d8:26:53:34:3f"
		n.setMacAdr(macAdr)
		assert macAdr == n.getMacAdr()

	def test_setLocation(self):
		n = node("0xfaca", "00:00:00:00:00:00:00:00", "0xffff")
		with pytest.raises(ValueError):
			n.setLocation("40.546765", "50.435667")
			n.setLocation("-100", "-45")
			n.setLocation("", "")
			n.setLocation("X", "X")
			n.setLocation("%", "-45.5525")

		lat = -45.256585
		lon = -29.546578
		n.setLocation(lat, lon)
		[r_lat, r_lon] = n.getLocation()
		assert r_lat == lat
		assert r_lon == lon

	def test_setSN(self):
		n = node("0xfaca", "00:00:00:00:00:00:00:00", "0xffff")
		with pytest.raises(ValueError):
			n.setSN("230432")
			n.setSN("ABCFF34454545")
			n.setSN("20145D34454545")

		n.setSN("2014030000855")
		assert 2014030000855 == n.getSN()

	def test_setCurNeighbors(self):
		neighbors = []
		n = node("0xfaca", "00:00:00:00:00:00:00:00", "0xffff")
		
		nei_nwk = ["0x0001", "0x0002", "0x0003"]
		nei_in = [7, 5, 3]
		nei_out = [7, 5, 3]

		for i in range(0,3):
			neighbors.append({"nwkAdr" : nei_nwk[i], "in_cost" : int(nei_in[i]), "out_cost" : int(nei_out[i])})
			n.setCurNeighbors(neighbors)
			curNei = n.getCurNeighbors()
			r_nei_nwk = curNei[i]["nwkAdr"]
			r_nei_in = curNei[i]["in_cost"]
			r_nei_out = curNei[i]["out_cost"]

			assert nei_nwk[i] == r_nei_nwk
			assert nei_in[i] == r_nei_in
			assert nei_out[i] == r_nei_out

	def test_addNpPreNeighbors(self):
		neighbors = []
		n = node("0xfaca", "00:00:00:00:00:00:00:00", "0xffff")
		
		nei_nwk = ["0x0001", "0x0002", "0x0003"]
		nei_in = [7, 5, 3]
		nei_out = [7, 5, 3]

		for i in range(0,3):
			neighbors.append({"nwkAdr" : nei_nwk[i], "in_cost" : int(nei_in[i]), "out_cost" : int(nei_out[i])})
	
		n.setCurNeighbors(neighbors)
		n.addNpPreNeighbors()
		np_list = n.getNpPreNeighbors()

		for np in np_list:
			#np is a list of neighbors
			for dic in np:
				#dic is a dictionary
				if (dic["nwkAdr"] == "0x0001"):
					assert dic["in_cost"] == 7
					assert dic["out_cost"] == 7
				elif (dic["nwkAdr"] == "0x0002"):
					assert dic["in_cost"] == 5
					assert dic["out_cost"] == 5
				elif (dic["nwkAdr"] == "0x0003"):
					assert dic["in_cost"] == 3
					assert dic["out_cost"] == 3

		nei_nwk = ["0x0004", "0x0005", "0x0006"]
		nei_in = [1, 3, 5]
		nei_out = [7, 5, 3]

		for i in range(0,3):
			neighbors.append({"nwkAdr" : nei_nwk[i], "in_cost" : int(nei_in[i]), "out_cost" : int(nei_out[i])})
	
		n.setCurNeighbors(neighbors)
		n.addNpPreNeighbors()
		np_list = n.getNpPreNeighbors()

		for np in np_list:
			#np is a list of neighbors
			for dic in np:
				#dic is a dictionary
				if (dic["nwkAdr"] == "0x0004"):
					assert dic["in_cost"] == 1
					assert dic["out_cost"] == 7
				elif (dic["nwkAdr"] == "0x0005"):
					assert dic["in_cost"] == 3
					assert dic["out_cost"] == 5
				elif (dic["nwkAdr"] == "0x0006"):
					assert dic["in_cost"] == 5
					assert dic["out_cost"] == 3

	def test_processPreNeighbors(self):
		neighbors = []
		n = node("0xfaca", "00:00:00:00:00:00:00:00", "0xffff")
		
		nei_nwk = ["0x0001", "0x0002", "0x0003"]
		nei_in = [7, 5, 3]
		nei_out = [7, 5, 3]

		for i in range(0,3):
			neighbors.append({"nwkAdr" : nei_nwk[i], "in_cost" : int(nei_in[i]), "out_cost" : int(nei_out[i])})
	
		nei_nwk = ["0x0001", "0x0002", "0x0003", "0x0004"]
		nei_in = [1, 3, 5, 1]
		nei_out = [1, 3, 5, 3]

		for i in range(0,4):
			neighbors.append({"nwkAdr" : nei_nwk[i], "in_cost" : int(nei_in[i]), "out_cost" : int(nei_out[i])})
	
		n.setCurNeighbors(neighbors)
		n.addNpPreNeighbors()
		n.processPreNeighbors()

		hist_list = n.getHistoricalNeighbors()
		for dic in hist_list:
			#dic is a dict
			if (dic["nwkAdr"] == "0x0001"):
				assert dic["tot_in_cost"] == 7+1
				assert dic["tot_out_cost"] == 7+1
			if (dic["nwkAdr"] == "0x0002"):
				assert dic["tot_in_cost"] == 5+3
				assert dic["tot_out_cost"] == 5+3
			if (dic["nwkAdr"] == "0x0003"):
				assert dic["tot_in_cost"] == 3+5
				assert dic["tot_out_cost"] == 3+5
			if (dic["nwkAdr"] == "0x0004"):
				assert dic["tot_in_cost"] == 1
				assert dic["tot_out_cost"] == 3

	def test_hasNeighbor(self):
		neighbors = []
		n = node("0xfaca", "00:00:00:00:00:00:00:00", "0xffff")
		
		nei_nwk = ["0x0001", "0x0002", "0x0003"]
		nei_in = [7, 5, 3]
		nei_out = [7, 5, 3]

		for i in range(0,3):
			neighbors.append({"nwkAdr" : nei_nwk[i], "in_cost" : int(nei_in[i]), "out_cost" : int(nei_out[i])})
	
		nei_nwk = ["0x0001", "0x0002", "0x0003", "0x0004"]
		nei_in = [1, 3, 5, 1]
		nei_out = [1, 3, 5, 3]

		for i in range(0,4):
			neighbors.append({"nwkAdr" : nei_nwk[i], "in_cost" : int(nei_in[i]), "out_cost" : int(nei_out[i])})
	
		n.setCurNeighbors(neighbors)
		n.addNpPreNeighbors()
		n.processPreNeighbors()

		assert n.hasNeighbor("0x0001", n.getHistoricalNeighbors()) == True
		assert n.hasNeighbor("0x0002", n.getHistoricalNeighbors()) == True
		assert n.hasNeighbor("0x0003", n.getHistoricalNeighbors()) == True
		assert n.hasNeighbor("0x0004", n.getHistoricalNeighbors()) == True
		assert n.hasNeighbor("0x0005", n.getHistoricalNeighbors()) == False
		assert n.hasNeighbor("0x0000", n.getHistoricalNeighbors()) == False
		assert n.hasNeighbor("0xFFFF", n.getHistoricalNeighbors()) == False

	def test_indexNeighbor(self):
		neighbors = []
		n = node("0xfaca", "12:34:56:78:9a:bc:de:ff", "0xffff")
		
		nei_nwk = ["0x0001", "0x0002", "0x0003"]
		nei_in = [7, 5, 3]
		nei_out = [7, 5, 3]

		for i in range(0,3):
			neighbors.append({"nwkAdr" : nei_nwk[i], "in_cost" : int(nei_in[i]), "out_cost" : int(nei_out[i])})
	
		nei_nwk = ["0x0001", "0x0002", "0x0003", "0x0004"]
		nei_in = [1, 3, 5, 1]
		nei_out = [1, 3, 5, 3]

		for i in range(0,4):
			neighbors.append({"nwkAdr" : nei_nwk[i], "in_cost" : int(nei_in[i]), "out_cost" : int(nei_out[i])})
	
		n.setCurNeighbors(neighbors)
		n.addNpPreNeighbors()
		n.processPreNeighbors()
		listOfDicts = n.getHistoricalNeighbors()

		nwk_list = ["0x0001", "0x0002", "0x0003", "0x0004"]
		for nwkAdr in nwk_list:
			index = n.indexNeighbor(nwkAdr, listOfDicts)
			assert index != -1
			dic = listOfDicts[index]
			assert dic["nwkAdr"] == nwkAdr 

		nwk_list = ["0x0005", "0x0006", "0xFFFF", "0xFFFE"]
		for nwkAdr in nwk_list:
			index = n.indexNeighbor(nwkAdr, listOfDicts)
			assert index == -1