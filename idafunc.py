import idaapi
import idc
import idabuty
import idafind
import idaobj


def make_reg_arg_opnd(arg_idx):
	ARG_REGS = dict(enumerate(['rcx', 'rdx', 'r8', 'r9']))

	if arg_idx in ARG_REGS.keys():
		return idaobj.IdaReg(None, ARG_REGS[arg_idx])
	else:
		return None


class Func(object):

	def __init__(self, f_ea):
		self.f = idaapi.get_func(f_ea)

	def make_arg_opnd(self, arg_idx):
		arg_opnd = make_reg_arg_opnd(arg_idx)
		if arg_opnd is not None:
			return arg_opnd
		else:
			od = '[rsp+arg_{}]'.format(idabuty.beautify_offset(8 * arg_idx))

			return idaobj.Opnd(ot=idc.o_displ, od=od)

	def find_nth_arg(self, arg_idx):
		return idafind.find(idc.PrevHead(self.f.startEA), self.make_arg_opnd(arg_idx))

	# TODO: Are you sure that ONLY ONE 'sub rsp, ???' exists in first bb?
	def find_stack_base(self):
		from_ea 	= idcnew.GetBB(self.f.startEA).endEA
		target_opnd	= idaobj.Opnd(ot=idc.o_reg, od='rsp')

		return idafind.find(from_ea, target_opnd, is_bwd=True)

	def find_mnem_eas(self, mnem):
		heads = idautils.Heads(self.f.startEA, self.f.endEA)
		mnem_eas = filter(lambda ea: idc.GetMnem(ea) == mnem, heads)

		return mnem_eas


class FuncCall(object):

	def __init__(self, ea):
		self.ea 	= ea
		self.func 	= Func(self.ea)

	def make_arg_opnd(self, arg_idx):
		arg_opnd = make_reg_arg_opnd(arg_idx)
		if arg_opnd is not None:
			return arg_opnd
		else:
			stack_base 	= self.func.find_stack_base().od
			offset 		= int(stack_base.rstrip('h'), 16) - (8 * arg_idx)
			od 			= '[rsp+{}+var_{}]'.format(stack_base, idabuty.beautify_offset(offset))
				
			return idaobj.Opnd(ot=idc.o_displ, od=od)

	def find_arg(self, arg_idx):
		return idafind.find(self.ea, self.get_arg_opnd(arg_idx), is_bwd=True)

	def find_args(self):
		args_dict = dict()

		arg_idx = 0
		try:
			while True:
				opnd 			= self.find_arg(arg_idx)
				args_dict[opnd] = arg_idx 					# reversed dictionary

				arg_idx += 1

		except NotFoundError:
			return args_dict

	def is_arg(self, arg_idx, target_opnd):
		try:
			return target_opnd == self.find_arg(arg_idx)

		except NotFoundError:
			return False