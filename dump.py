import idaapi

import idcnew
import idabuty
import idaobj
import idafind
import idafunc


__author__ = 'dohki'


def get_drv_entry():
	exports = idautils.Entries()

	# alternative: f_ea = idc.BeginEA()
	f_ea = filter(lambda args: args[3] == 'DriverEntry', exports)[0][2]

	last_ea		= idc.PrevHead(idaapi.get_func(f_ea).endEA)
	last_mnem	= idc.GetMnem(last_ea)

	assert last_mnem.startswith('ret') or last_mnem == 'jmp'

	if last_mnem == 'jmp':
		opnd_type 	= idcnew.GetOpType(last_ea, 0)
		opnd 		= idcnew.GetOpnd(last_ea, 0)

		if opnd_type in [idc.o_mem, idc.o_near]:
			f_ea = idc.LocByName(opnd)
		elif idcnew.GetOpType(last_ea, 0) == idc.o_reg:
			f_ea = idaobj.IdaReg(last_ea, opnd).trace_val()
		else:
			raise NotImplementedError
		
	return DriverEntry(f_ea)


# TODO: ABC
# TODO: refactoring
class DriverEntry(idafunc.Func):
	def __init__(self, f_ea):
		self.super().__init__(f_ea)

	def super(self):
		return super(DriverEntry, self)

	def find_drv_obj(self):
		return self.super().find_nth_arg(0)

	def find_dispatch_dev_ctrl(self):
		print idabuty.beautify_title('DriverObject:'), self.find_drv_obj()

		for ea in idautils.Heads(self.f.startEA, self.f.endEA):
			if idc.GetMnem(ea) == 'mov':
				opnd = idaobj.Opnd(ea=ea, oi=0)
				if opnd.ot == idc.o_displ:
					parsed_opnd = opnd.parse()

					if len(parsed_opnd) == 2:
						pass
						#print idabuty.beautify_ea(ea)

					if len(parsed_opnd) == 3:
						base_reg, idx, displ = parsed_opnd

						# ['rcx', 'rax', '70h']
						if ('*' not in idx) and (not idx.endswith('h')):
							idx_reg = idx

							opnd1			= self.find_drv_obj()														# mov     [rsp+drv_obj], rcx
							opnd2			= idafind.find(ea, idaobj.Opnd(ot=idc.o_reg, od=base_reg), is_bwd=1)	# mov     rcx, [rsp+48h+drv_obj]	
							is_drv_obj		= idaobj.cmp_od_displ(opnd1, opnd2)

							opnd 			= idafind.find(ea, idaobj.Opnd(ot=idc.o_reg, od=idx_reg), is_bwd=True)
							is_mj_dev_ctrl	= '0Eh' == idaobj.parse_opnd(opnd)

							is_mj_func		= '70h' == displ

							if is_drv_obj and is_mj_dev_ctrl and is_mj_func:
								return idafind.get_func_from_opnd(idaobj.Opnd(ea=ea, oi=1))

		raise idafind.NotFoundError


class DispatchDeviceControl(idafunc.Func):
	def __init__(self, f_ea):
		self.super().__init__(f_ea)
		self.ioctl_dict = self.find_ioctl_dict()

		print 'IOCTL dict:', idabuty.beautify_ea(self.ioctl_dict)

	def super(self):
		return super(DispatchDeviceControl, self)

	def find_irp(self):
		return self.super().find_arg(1)

	def find_io_stack_loc(self):
		irp_opnd = self.find_irp()
		print beautify_title('IRP:'), irp_opnd

		call_eas = self.find_mnem_eas('call')
		call_eas = filter(lambda ea: idafind.is_func_call_arg(self.f, ea, 0, irp_opnd), call_eas)
		call_eas = filter(lambda ea: 'IofCompleteRequest' not in idcnew.GetOpnd(ea, 0), call_eas)

		assert len(call_eas) == 1 # TODO: check +0B8h

		return idafind.find(call_eas[0], idaobj.Opnd(ot=idc.o_reg, od='rax'))

	def get_ioctl_dict(self):
		io_stack_loc_opnd = self.find_io_stack_loc()
		print beautify_title('IO_STACK_LOCATION:'), io_stack_loc_opnd

		out_buf_len_opnd	= idafind.find_struct_member(io_stack_loc_opnd, 8)
		in_buf_len_opnd		= idafind.find_struct_member(io_stack_loc_opnd, 16)
		ioctl_code_opnd		= idafind.find_struct_member(io_stack_loc_opnd, 24)

		return dict(out_buf_len_opnd=out_buf_len_opnd, in_buf_len_opnd=in_buf_len_opnd, ioctl_code_opnd=ioctl_code_opnd)

	def __get_ioctl_args(self, ea):
		try:
			ea = idafind.find_displ_fwd(ea, is_recur=True, ea=ea, oi=0)
			displ = idaobj.get_displ(ea, 0)

			cmp_eas = idafind.get_mnem_eas(self.f, 'cmp')
			cmp_eas = filter(lambda ea: idaobj.get_displ(ea=ea, oi=0) == displ, cmp_eas)
		
			ioctl_codes = map(lambda ea: idaobj.parse_opnd(ea=ea, oi=1), cmp_eas)

			return ioctl_codes
		except:
			return []

	def get_out_buf_lens(self):
		return self.__get_ioctl_args(self.__ioctl_dict['out_buf_len_ea'])

	def get_in_buf_lens(self):
		return self.__get_ioctl_args(self.__ioctl_dict['in_buf_len_ea'])

	def get_ioctl_codes(self):
		call_eas	= idafind.get_mnem_eas(self.f, 'call')
		call_args	= map(lambda ea: idafind.find_func_call_args(self.f, ea), call_eas)
		for call_arg in call_args:
			for k, v in call_arg.iteritems():
				print k, v
			print '-' * 50

		#return self.__get_ioctl_args(self.__ioctl_dict['ioctl_code_ea'])


if __name__ == '__main__':
	# TODO: support for 32 bits
	assert idaapi.get_inf_structure().is_64bit()

	print '-' * 100

	drv_entry = get_drv_entry()
	print idabuty.beautify_title('DriverEntry:'), idabuty.beautify_ea(drv_entry.f.startEA)

	dispatch_dev_ctrl = drv_entry.find_dispatch_dev_ctrl()
	print idabuty.beautify_title('DispatchDeviceControl:'), idabuty.beautify_ea(dispatch_dev_ctrl.f.startEA)

	ioctl_codes = dispatch_dev_ctrl.get_ioctl_codes()
	print idabuty.beautify_title('IOCTL codes:'), ioctl_codes