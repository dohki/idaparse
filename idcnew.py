import idaapi
import idc
import idabuty

# IDAPython bug
def adjust_opnd_idx(ea, opnd_idx):
	if (idc.GetMnem(ea) == 'imul') and (opnd_idx == 1):
		return 2
 	else:
 		return opnd_idx

def GetOpType(ea, opnd_idx):
	return idc.GetOpType(ea, adjust_opnd_idx(ea, opnd_idx))

def GetOpnd(ea, opnd_idx):
	return idc.GetOpnd(ea, adjust_opnd_idx(ea, opnd_idx))

def GetOperandValue(ea, opnd_idx):
	return idc.GetOperandValue(ea, adjust_opnd_idx(ea, opnd_idx))


# bb: Basic Block (IDA naming convention)	
def GetBB(ea):
	bbs = idaapi.FlowChart(idaapi.get_func(ea))
	bbs = filter(lambda bb: bb.startEA <= ea and ea < bb.endEA, bbs)
	
	# TODO: return None if len(bbs) != 1
	assert len(bbs) <= 1

	if len(bbs) == 0:
		return None
	elif len(bbs) == 1:
		return bbs[0]


def NthHead(ea, dist):
	if dist == 0:
		return ea
	elif dist < 0:
		return NthHead(idc.PrevHead(ea), dist + 1)
	elif dist > 0:
		return NthHead(idc.NextHead(ea), dist - 1)