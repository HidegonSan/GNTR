try:
	import gdb
except ImportError:
	import sys
	print("Run in GDB.\narm-none-eabi-gdb -q -x " + __file__)
	sys.exit(1)


import binascii
import struct
import sys
import itertools


class GNTR(object):


	def __init__(self, ip, pid):
		self.__ip = ip
		self.__pid = str(pid)
		self.__connecting = False
		self.__connected = False


	def __run(self, cmd):
		return gdb.execute(cmd, to_string=True)


	def connect(self):
		if not self.__connecting:
			self.__connecting = True
			if not self.__connected:
				self.__connected = True
				self.__run("set confirm 0")
				self.__run("set pagination off") # 巨大なページになったときに次のページへ行く確認をしない
				self.__run("target extended-remote " + self.__ip + ":4000") # extended-modeはデバッグ対象を決めないので下のattachが必要となる
				self.__run("attach " + self.__pid)
			else:
				self.__run("attach " + self.__pid)


	def disconnect(self):
		if self.__connected and self.__connecting:
			self.__connecting = False
			self.__run("detach")


	def quit(self):
		if self.__connected:
			if self.__connecting:
				self.disconnect()
			self.__connecting = False
			self.__run("quit")


	def write32(self, address, value):
		self.connect()
		self.__run("set *" + hex(address) + "=" + hex(value))


	def write16(self, address, value):
		self.connect()
		self.write32(address, int(hex(self.read32(address))[2:].zfill(8)[:4] + hex(value)[2:].zfill(4), 16))


	def write8(self, address, value):
		self.connect()
		self.write32(address, int(hex(self.read32(address))[2:].zfill(8)[:6] + hex(value)[2:].zfill(2), 16))


	def write_float(self, address, value):
		self.write32(address, struct.unpack("<I", struct.pack("<f", value))[0])


	def read32(self, address):
		self.connect()
		ret = self.__run("x/1wx" + hex(address))
		return int(ret[ret.find("	0x") + 3:].upper().strip(), 16)


	def read16(self, address):
		self.connect()
		ret = self.__run("x/1hx" + hex(address))
		return int(ret[ret.find("	0x") + 3:].upper().strip(), 16)


	def read8(self, address):
		self.connect()
		ret = self.__run("x/1bx" + hex(address))
		return int(ret[ret.find("	0x") + 3:].upper().strip(), 16)


	def read_float(self, address):
		return struct.unpack(">f", binascii.unhexlify(hex(self.read32(address))[2:]))[0]


	def read_asm(self, address):
		return self.read_range_asm(address, 1)


	def __read_range(self, address, amount, unit):
		self.connect()
		ret = self.__run("x /" + str(amount) + unit + "x " + str(address))
		values = []
		splitted_lines = [line.split("\t") for line in ret.split("\n")]
		flatten_lines = list(itertools.chain.from_iterable(splitted_lines))
		for value in flatten_lines:
			# 先頭のアドレス表示と空の要素を除く
			if value.find(":") == -1 and value:
				values.append(int(value, 16))
		return values


	def read_range32(self, address, amount):
		return self.__read_range(address, amount, "w")


	def read_range16(self, address, amount):
		return self.__read_range(address, amount, "h")


	def read_range8(self, address, amount):
		return self.__read_range(address, amount, "b")


	def read_range_asm(self, address, amount):
		self.connect()
		ret = self.__run("x /" + str(amount) + "wi " + str(address))
		values = []
		for line in ret.split("\n"):
			line = line.split("\t")
			del line[0] # アドレスを削除
			values.append(" ".join(line))
		del values[-1] # 空要素を削除
		return values


	def read_range32_by_address(self, address_from, address_to):
		return self.read_range32(address_from, (address_to - address_from) // 4)


	def read_range16_by_address(self, address_from, address_to):
		return self.read_range16(address_from, (address_to - address_from) // 2)


	def read_range8_by_address(self, address_from, address_to):
		return self.read_range8(address_from, (address_to - address_from))


	def read_range_asm_by_address(self, address_from, address_to):
		return self.read_range_asm(address_from, (address_to - address_from) // 4)


	def get_regsisters(self):
		registers = [i for i in self.__run("i r").split(" ") if i]
		ret = {
						"r0": registers[1],
						"r1": registers[3],
						"r2": registers[5],
						"r3": registers[7],
						"r4": registers[9],
						"r5": registers[11],
						"r6": registers[13],
						"r7": registers[15],
						"r8": registers[17],
						"r9": registers[19],
						"r10": registers[21],
						"r11": registers[23],
						"r12": registers[25],
						"sp": registers[27],
						"lr": registers[29],
						"pc": registers[31],
						"cpsr": registers[33],
						"fpscr": registers[35],
						"fpexc": registers[37],
		}
		return ret
