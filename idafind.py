import idaapi
import idautils
import idc, idcnew
import idabuty
import idaobj


__author__ = 'dohki'


def find(from_ea, target_obj, is_recur=True, is_bwd=False, is_opposite=False, is_trace=True):

	def get_opnd_idx(is_writing):
		return 1 if is_writing else 0

	def get_opposite_opnd_idx(opnd_idx):
		assert opnd_idx in [0, 1]

		return 1 - opnd_idx

	def is_matched(ea, opnd_idx, target_obj):
		WRITE_MNEM	= ['mov', 'lea', 'imul', 'sub']	# TBU

		obj = idaobj.IdaObj.from_opnd(ea, opnd_idx)

		'''
		if obj == target_obj:
			print obj, '|', target_obj
		'''

		return (idc.GetMnem(ea) in WRITE_MNEM) and (obj == target_obj)
	
	is_fwd = not is_bwd

	adjusted_ea = idc.NextHead(from_ea)	if is_fwd else idc.PrevHead(from_ea)
	bb 			= idcnew.GetBB(adjusted_ea)

	# from_ea exclusive
	start_ea	= idc.NextHead(from_ea)	if is_fwd else bb.startEA
	end_ea		= bb.endEA 				if is_fwd else from_ea
	
	heads = idautils.Heads(start_ea, end_ea)
	if is_bwd:
		heads = reversed(list(heads))

	# is_fwd == is_writing
	self_opnd_idx = get_opnd_idx(is_fwd)
	if is_opposite:
		self_opnd_idx = get_opposite_opnd_idx(self_opnd_idx)
	other_opnd_idx = get_opposite_opnd_idx(self_opnd_idx)

	until_cond 	= lambda ea: is_matched(ea, other_opnd_idx,	target_obj)
	find_cond	= lambda ea: is_matched(ea, self_opnd_idx,	target_obj)
	make_obj	= lambda ea: idaobj.IdaObj.from_opnd(ea, other_opnd_idx)
	trace_cond	= lambda ea: idcnew.GetOpType(ea, other_opnd_idx) == idc.o_reg
	trace 		= lambda ea: find(ea, make_obj(ea), is_recur, is_bwd, is_opposite, is_trace)
	
	for ea in heads:

		# TODO: What about xor rcx, rcx?
		if until_cond(ea):
			return None

		if find_cond(ea):
			if is_trace and trace_cond(ea):
				return trace(ea)	
			else:
				return make_obj(ea)

	if is_recur:
		
		# TODO: IDAPython bug - bb.preds() always returns empty list.
		if is_bwd:
			raise NotImplementedError

		next_bbs 		= bb.succs() 							if is_fwd else bb.preds()

		# not deterministic
		if len(list(next_bbs)) != 1:
			return None

		next_from_ea 	= idcnew.PrevHead(next_bbs[0].startEA) 	if is_fwd else next_bbs[0].endEA

		return find(next_from_ea, target_obj, is_recur, is_bwd, is_opposite, is_trace)
	else:
		return None


def find_struct_member(struct_obj, offset):
	assert type(struct_obj) == idaobj.obj

	def make_member_od(tmp_struct_obj, offset):
		return '[{}+{}]'.format(tmp_struct_obj.od, idabuty.beautify_offset(offset))

	ea = struct_obj.ea
	while True:
		tmp_struct_obj		= find(ea, struct_obj, is_recur=False)
		target_member_obj	= idaobj.obj(ot=idc.o_displ, od=make_member_od(tmp_struct_obj, offset))
		member_obj			= find(tmp_struct_obj.ea, target_member_obj)

		return member_obj