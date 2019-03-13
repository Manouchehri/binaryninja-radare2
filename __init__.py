from binaryninja import *
from binaryninja.plugin import BackgroundTaskThread
import r2pipe

class LinearSweeper(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, 'Linear sweeping...')
        self.bv = bv

    def run(self):
        bin_filename = self.bv.file.original_filename

        log.log_info("[r2] Starting analysis ({})".format(bin_filename))
        r2p = r2pipe.open(bin_filename)
        r2p.cmd('aaa')
        r2functions = r2p.cmdj('aflj')
        log.log_debug(str(r2functions))
        r2comments = r2p.cmdj('CCj')
        r2p.quit()

        log.log_info("[r2] Updating functions")
        for r2function in r2functions:
            addr = r2function['offset']
            bjfunc = self.bv.get_function_at(addr)

            if bjfunc is None:
                self.bv.add_function(addr, plat=self.bv.platform) # should do r2function['name'] as well
                if self.bv.get_function_at(addr) is None:
                    log.log_warn('Cannot create function! Addr: 0x{:X}'.format(addr))
                    continue

            bjfunc = self.bv.get_function_at(addr)
            if 'fcn.' not in r2function['name']:
                log.log_info('Rename function "{}" -> "{}"'.format(
                    bjfunc.name,
                    r2function['name']
                ))

                bjfunc.name = r2function['name']
            
        self.bv.reanalyze()
        
        log.log_info("[r2] Updating comments")
        # add helper comments
        for comment in r2comments:
            addr = comment['offset']
            comm = comment['name']
            
            functions = self.bv.get_functions_containing(addr)
            if functions is not None:
                for func in functions:
                    func.set_comment_at(addr, comm)

            else:
                log.log_warn('Cannot find function! Addr: 0x{:X}, Comment: "{}"'.format(addr, comm))

        self.bv.reanalyze()
        log.log_info("[r2] Done")

def spawn(bv):
    ls = LinearSweeper(bv)
    ls.start()

PluginCommand.register("r2 LineSweep", "Run radare2", spawn)
