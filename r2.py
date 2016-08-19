from binaryninja import *
import r2pipe

def spawn(bv):
	r2p = r2pipe.open(bv.file.filename)
	r2p.cmd('aaa')
	r2functions = r2p.cmdj('aflj')
	r2p.quit()

	for r2function in r2functions:
		bv.add_function(bv.platform, r2function['offset'])  # should do r2function['name'] as well

PluginCommand.register("radare2", "Run radare2", spawn)
