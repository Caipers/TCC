# content of test_class.py
import pytest
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



