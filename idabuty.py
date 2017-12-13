# You can easily jump to certain instruction by double-clicking beautifed ea.
def beautify_ea(node):
	if type(node) == long:
		return '{:x}'.format(node)
	elif type(node) == list:
		return map(beautify_ea, node)
	elif type(node) == dict:
		return dict(map(lambda (k, v): (beautify_ea(k), beautify_ea(v)), node.iteritems()))
	else:
		return node.__str__()

def beautify_offset(offset):
	return '{:x}h'.format(offset)

def beautify_title(title):
	return '{:20}'.format(title)