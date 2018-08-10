from binaryninja import *
from binaryninja.plugin import BackgroundTaskThread
import r2pipe

class LinearSweeper(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, 'Linear sweeping...')
        self.bv = bv

    def run(self):
        r2p = r2pipe.open(self.bv.file.filename)
	r2p.cmd('aaaa')
	r2functions = r2p.cmdj('aflj')
        r2comments = r2p.cmdj('CCj')
	r2p.quit()

	for r2function in r2functions:
            self.bv.add_function(r2function['offset'], plat=self.bv.platform)	 # should do r2function['name'] as well
            
        self.bv.reanalyze()
        
        # add helper comments
        for comment in r2comments:
            addr = comment['offset']
            comm = comment['name']
            
            functions = self.bv.get_functions_containing(addr)
            if functions is not None:
                for func in functions:
                    func.set_comment_at(addr, comm)

            else:
                log.log_warn('Cannot find function! Addr: 0xx{:X}, Comment: "{}"'.format(addr, comm))
	
        self.bv.reanalyze()

def spawn(bv):
    ls = LinearSweeper(bv)
    ls.start()

PluginCommand.register("r2 LineSweep", "Run radare2", spawn)
