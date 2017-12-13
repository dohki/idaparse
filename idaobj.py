import six, abc
import re
import idc, idcnew
import idabuty
import idafind


__author__ = 'dohki'


class InvalidError(Exception):
	pass		


@six.add_metaclass(abc.ABCMeta)
class IdaObj(object):

	# ea: Effective Address (IDA Naming Convetion)
	def __init__(self, ea=None, opnd_idx=None, type=None, raw=None):
		self.ea 		= ea
		self.opnd_idx 	= opnd_idx

		if self.is_opnd():
			self.type	= idcnew.GetOpType(ea, opnd_idx)
			self.raw	= idcnew.GetOpnd(ea, opnd_idx)
		else:
			self.type 	= type
			self.raw 	= raw

	@abc.abstractmethod
	def __eq__(self):
		pass

	def __str__(self):
		return 'ea: {}, type: {}, raw: {}'.format(idabuty.beautify_ea(self.ea), self.type, self.raw)

	def is_opnd(self):
		return self.opnd_idx is not None

	@staticmethod
	def from_opnd(ea, opnd_idx):
		opnd_type = idcnew.GetOpType(ea, opnd_idx)
		if opnd_type == idc.o_reg:
			return IdaReg.from_opnd(ea, opnd_idx)
		elif opnd_type in [idc.o_phrase, idc.o_displ]:
			return IdaMem.from_opnd(ea, opnd_idx)
		else:
			return idcnew.GetOpnd(ea, opnd_idx)


class IdaReg(IdaObj):

	def __init__(self, ea, raw):
		self.super().__init__(ea=ea, type=idc.o_reg, raw=raw)
		
		self.id = self.get_id()

	@classmethod
	def from_opnd(cls, ea, opnd_idx):
		instance = cls.__new__(cls)
		instance.super().__init__(ea=ea, opnd_idx=opnd_idx)
	
		assert instance.type == idc.o_reg

		instance.__init__(instance.ea, instance.raw)

		return instance

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented

		return self.id == other.id

	def super(self):
		return super(IdaReg, self)

	def get_id(self):
		m = re.match('[re]?([abcds][ip]?)[xhl]?', self.raw)
		if m is not None:
			return m.group(1)
		else:
			m = re.match('r(\d{1,2})[dwb]?', self.raw)
			if m is not None:
				return m.group(1)
			else:
				raise InvalidError

	def trace_val(self):
		expr = '{}'
		obj = self
		while True:
			obj = idafind.find(obj.ea, obj, is_recur=False, is_bwd=True, is_trace=False)

			mnem = idc.GetMnem(obj.ea)
			if mnem in ['mov', 'lea']:
				expr 	= expr.format(opnd.raw)
				break

			# TODO: What about xor rcx, rcx?
			elif mnem == 'xor':
				expr 	= expr.format(0)
				break

			try:
				FMT		= '({{}}) {} {}'
				OP_DICT = {
					'imul': '*',
					}

				expr 	= expr.format(FMT.format(OP_DICT[mnem], obj.raw))

			except KeyError:
				raise NotImplementedError

		try:
			return eval(expr)
		except:
			return expr


# TODO: I don't know the difference between idc.o_phrase and idc.o_displ.
class IdaMem(IdaObj):

	def __init__(self, ea, raw_base_reg, offset):
		raw = '[{}+{}]'.format(raw_base_reg, idabuty.beautify_offset(offset))
		self.super().__init__(ea=ea, type=idc.o_displ, raw=raw)

		self.base_reg 	= IdaReg(ea, raw_base_reg)
		self.offset 	= offset

	@classmethod
	def from_opnd(cls, ea, opnd_idx):
		instance = cls.__new__(cls)
		instance.super().__init__(ea=ea, opnd_idx=opnd_idx)

		assert instance.type in [idc.o_phrase, idc.o_displ]

		instance.__init__(ea, instance.get_base_reg().raw, instance.get_offset())

		return instance

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented

		base_reg_match 	= self.base_reg == other.base_reg
		offset_match	= self.offset == other.offset
		
		return base_reg_match and offset_match

	def super(self):
		return super(IdaMem, self)

	def parse(self):
		return re.match('\[([\w+]*)\]', self.raw).group(1).split('+')

	def get_base_reg(self):
		if getattr(self, 'base_reg', None) is None:
			self.base_reg = IdaReg(self.ea, self.parse()[0])

		return self.base_reg

	def get_offset(self):
		if getattr(self, 'offset', None) is None:

			def get_idx():
				try:
					return IdaReg(self.ea, self.parse()[1]).trace_val()
				except InvalidError:
					return 0

			def get_displ():
				return idcnew.GetOperandValue(self.ea, self.opnd_idx)

			self.offset = get_idx() + get_displ()

		return self.offset