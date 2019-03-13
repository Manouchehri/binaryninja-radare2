from binaryninja import *
from binaryninja.plugin import BackgroundTaskThread
import r2pipe

class LinearSweeper(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, 'Linear sweeping...')
        self.bv = bv

    def update_functions(self, r2functions):
        log.log_info("[r2] Updating functions")
        for r2function in r2functions:
            addr = r2function['offset']
            bjfunc = self.bv.get_function_at(addr)

            # check if detected function from radare is not created alredy
            if bjfunc is None:
                self.bv.add_function(addr, plat=self.bv.platform)
                
                if self.bv.get_function_at(addr) is None:
                    log.log_warn('Cannot create function! Addr: 0x{:X}'.format(addr))
                    continue

            # rename only if new name is not using r2 standard prefix
            # and detected function is not recognized by binja
            bjfunc = self.bv.get_function_at(addr)
            if 'fcn.' not in r2function['name'] and 'sub_' in bjfunc.name:
                log.log_info('Rename function "{}" -> "{}"'.format(
                    bjfunc.name,
                    r2function['name']
                ))
                bjfunc.name = r2function['name']

    def update_comments(self, r2comments):
        # add radare commands
        log.log_info("[r2] Updating comments")
        for comment in r2comments:
            addr = comment['offset']
            comm = comment['name']
            
            functions = self.bv.get_functions_containing(addr)
            if functions is not None:
                for func in functions:
                    func.set_comment_at(addr, comm)

            else:
                log.log_warn('Cannot find function! Addr: 0x{:X}, Comment: "{}"'.format(addr, comm))


    def run(self):
        bin_filename = self.bv.file.original_filename

        log.log_info("[r2] Starting analysis ({})".format(bin_filename))
        r2p = r2pipe.open(bin_filename)
        r2p.cmd('aaa')

        self.update_functions(r2p.cmdj('aflj'))
        self.update_comments(r2p.cmdj('CCj'))

        log.log_info("[r2] Done")
        r2p.quit()

def spawn(bv):
    ls = LinearSweeper(bv)
    ls.start()

PluginCommand.register("Radare2 Analysis", "Import functions and comments", spawn)
