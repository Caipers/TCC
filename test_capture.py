import pytest
import sys

from capture import capture

class TestClass:
	"""
	Unit test for capture class
	"""

	def test_convStrtoFF(self):
		cap = capture()
		# test to pass
		assert "0x08" == cap.convStrtoFF("0x8")
		assert "0xff" == cap.convStrtoFF("0xff")
		assert "0xff" == cap.convStrtoFF("0xFF")
		assert "0xff" == cap.convStrtoFF("0xfF")
		assert "0x08" == cap.convStrtoFF("8")
		assert "0x0a" == cap.convStrtoFF("10")
		assert "0x0f" == cap.convStrtoFF("15")
		assert "0xff" == cap.convStrtoFF("255")

		# test to fail
		assert None == cap.convStrtoFF("")
		assert None == cap.convStrtoFF(1234)
		assert None == cap.convStrtoFF("1234")
		assert None == cap.convStrtoFF("gg")
		assert None == cap.convStrtoFF("$$")
		assert None == cap.convStrtoFF("0xFfFf")
		assert None == cap.convStrtoFF("0xgggg")
		assert None == cap.convStrtoFF("0xgg")
		assert None == cap.convStrtoFF("0xzz")
		assert None == cap.convStrtoFF("0xz")

	def test_convStrtoFFFF(self):
		cap = capture()
		# test to pass
		assert "0x0008" == cap.convStrtoFFFF("0x8")
		assert "0x00ff" == cap.convStrtoFFFF("0xff")
		assert "0x00ff" == cap.convStrtoFFFF("0xFF")
		assert "0x02ff" == cap.convStrtoFFFF("0x2FF")
		assert "0xffff" == cap.convStrtoFFFF("0xFfFf")
		assert "0x0008" == cap.convStrtoFFFF("8")
		assert "0x000a" == cap.convStrtoFFFF("10")
		assert "0x000f" == cap.convStrtoFFFF("15")
		assert "0x00ff" == cap.convStrtoFFFF("255")
		assert "0xffff" == cap.convStrtoFFFF("65535")

		# test to fail
		assert None == cap.convStrtoFFFF("")
		assert None == cap.convStrtoFFFF(65536)
		assert None == cap.convStrtoFFFF("65536")
		assert None == cap.convStrtoFFFF("0xfffff")
		assert None == cap.convStrtoFFFF("gg")
		assert None == cap.convStrtoFFFF("$$")
		assert None == cap.convStrtoFFFF("$$$$")
		assert None == cap.convStrtoFFFF("$$$$##")
		assert None == cap.convStrtoFFFF("0xgggg")
		assert None == cap.convStrtoFFFF("0xgg")
		assert None == cap.convStrtoFFFF("0xzz")
		assert None == cap.convStrtoFFFF("0xz")