import sys
sys._getframe().f_globals['__name__'] = '__main__' # Hack to bypass angr's frame check
import angr

def loadBinary(s):
    b = angr.Project(s, load_options={'auto_load_libs':False, 'main_opts': {'custom_base_addr': 0x0}})
    return b.filename
