from binaryninja import *
from binaryninja.plugin import BackgroundTaskThread
import r2pipe

class LinearSweeper(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, 'Linear sweeping...')
        self.bv = bv

    def run(self):
        r2p = r2pipe.open(self.bv.file.filename)
	r2p.cmd('aaa')
	r2functions = r2p.cmdj('aflj')
	r2p.quit()

	for r2function in r2functions:
            self.bv.add_function(r2function['offset'], plat=self.bv.platform)	 # should do r2function['name'] as well
	self.bv.reanalyze()

def spawn(bv):
    ls = LinearSweeper(bv)
    ls.start()

PluginCommand.register("radare2", "Run radare2", spawn)
