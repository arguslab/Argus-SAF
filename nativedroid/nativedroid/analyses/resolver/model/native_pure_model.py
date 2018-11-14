import logging

from angrutils import *

from nativedroid.analyses.resolver.model import android_app_model
from nativedroid.analyses.resolver.model.anativeactivity_model import ANativeActivity

__author__ = "Xingwei Lin"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"

nativedroid_logger = logging.getLogger('native_pure_model')
nativedroid_logger.setLevel(logging.INFO)


class CallbackHook(angr.SimProcedure):
    """
    Hook callback functions.
    """

    NO_RET = False

    # IS_FUNCTION = True

    def run(self, callbacks=None, argument=None):
        """
        Hook callback functions.
        :param callbacks: Callback functions addresses.
        :param argument: argument
        :return:
        """

        for key, value in callbacks.iteritems():
            self.call(value, [argument], 'final_call')

    # noinspection PyUnusedLocal
    def final_call(self, callbacks=None, argument=None):
        self.exit(0)


class EnvMethodModel:

    def __init__(self):
        pass

    @staticmethod
    def get_function_addr_range(cfg, func_name):
        """
        Get address range of given function.
        :param cfg: CFG object
        :param func_name: function name
        :return: address range of given function
        """
        func = cfg.kb.functions.function(name=func_name)
        if func:
            start = func.addr
            end = sorted(list(func.block_addrs_set))[-1]
            return start, end
        else:
            nativedroid_logger.error('%s doesn\'t exist' % func_name)
            return 0, 0x8000000

    @staticmethod
    def count_stash_instructions(project, stash):
        """
        Count instructions size from stash.

        :param project:
        :param stash:
        :return: Instructions size
        :rtype: int
        """
        stash_instructions = 0
        for bbl_addr in stash.history.bbl_addrs:
            block = project.factory.block(bbl_addr)
            block_instructions = len(block.instruction_addrs)
            stash_instructions += block_instructions
        # print('Total INS: %d' % total_instructions)
        return stash_instructions

    @staticmethod
    def count_cfg_instructions(cfg):
        """
        Count instructions size from CFG.

        :param CFGAccurate cfg: CFG.
        :return: Instructions size
        :rtype: int
        """
        total_instructions = 0
        for func_addr, func in cfg.kb.functions.iteritems():
            func_instructions = 0
            # print func.name
            for block in func.blocks:
                if block.size > 0:
                    block_instructions = len(block.instruction_addrs)
                else:
                    block_instructions = 0
                # print block, block_instructions
                func_instructions += block_instructions
            total_instructions += func_instructions
        # print('Total INS: %d' % total_instructions)
        return total_instructions

    @staticmethod
    def glue_callback_signature(project):
        """
        Find two callback functions symbols based on matching signature of the two callback functions.
    
        :param project: loaded binary file
        :return: two callback functions symbols
        """

        demangled_names_keys = project.loader.main_object.demangled_names.keys()
        input_callback_signature = None
        cmd_callback_signature = None
        for key in demangled_names_keys:
            # signature of handle_input function must end with 'P11android_appP11AInputEvent'
            if key.endswith('P11android_appP11AInputEvent'):
                input_callback_signature = key
                # print "input_callback_signature: ", input_callback_signature

            # signature of handle_cmd function must end with 'P11android_appi'
            if key.endswith('P11android_appi'):
                cmd_callback_signature = key
                # print "cmd_callback_signature: ", cmd_callback_signature

        input_callback_symbol = project.loader.main_object.get_symbol(input_callback_signature)
        # print "input_callback address: ", hex(input_callback_symbol.rebased_addr)
        cmd_callback_symbol = project.loader.main_object.get_symbol(cmd_callback_signature)
        # print "cmd_callback address: ", hex(cmd_callback_symbol.rebased_addr)
        callback_symbol = [input_callback_symbol, cmd_callback_symbol]
        return callback_symbol

    def glue_callback(self, project, start_state_addr, find_addr):
        """
        Native activity based on 'android_native_app_glue' lib. We focus on two callback functions(android_app->onAppCmd & android_app->onInputEvent).
        :param project: binary file
        :param start_state_addr: android_main address, which is the begin address of path_group.We just simulate execution android_main to run over struct assignment.
        :param find_addr: For there is while loop in android_main, we set a find_addr to end the execution.The find_addr we set is source->process instruction address
        :return: glue_callback dict, stash instructions
        """
        # construct android_app struct prototype
        android_app_struct = angr.sim_type.define_struct(
            'struct android_app {void* userData; void (*onAppCmd)(void* app, int cmd); int (*onInputEvent)(void* app, int event); int activity; int config; void* savedState; int savedStateSize; int looper; int inputQueue; int window; int contentRect; int activityState; int destroyRequested; int mutex; int cond; int msgread; int msgwrite; int thread; struct android_poll_source {int id; void* app; void* process;} cmdPollSource; struct android_poll_source {int id; void* app; void* process;} inputPollSource; int running; int stateSaved; int destroyed; int redrawNeeded; int pendingInputQueue; int pendingWindow; int pendingContentRect;};')
        # set struct android_app* state address in binary
        pointer_arg = claripy.BVV(0x800000, 32)
        call_state = project.factory.call_state(start_state_addr, pointer_arg, add_options={angr.options.CALLLESS})
        # nativedroid_logger.info('Start symbolic execution')
        simgr = project.factory.simgr(call_state)
        limiter = angr.exploration_techniques.LengthLimiter(max_length=15)
        simgr.use_technique(limiter)
        try:
            simgr.explore(find=find_addr, num_find=1)
            if simgr.cut:
                state_after = simgr.cut[0]
                stash_instructions = 0
                for cut_stash in simgr.cut:
                    stash_instruction = self.count_stash_instructions(project, cut_stash)
                    stash_instructions += stash_instruction
            elif simgr.deadended:
                state_after = simgr.deadended[0]
                stash_instructions = 0
                for deadended_stash in simgr.deadended:
                    stash_instruction = self.count_stash_instructions(project, deadended_stash)
                    stash_instructions += stash_instruction
            elif simgr.found:
                state_after = simgr.found[0]
                stash_instructions = 0
                for found_stash in simgr.found:
                    stash_instruction = self.count_stash_instructions(project, found_stash)
                    stash_instructions += stash_instruction
            else:
                return None, 0
            android_app_struct_values = android_app_struct.with_arch(project.arch).extract(state_after,
                                                                                           0x800000)._values
            glue_callback_dict = {'onAppCmd': android_app_struct_values['onAppCmd'].args[0],
                                  'onInputEvent': android_app_struct_values['onInputEvent'].args[0]}
        except Exception as e:
            nativedroid_logger.error('Exception: %s' % e)
            stash_instructions = 0
            glue_callback_dict = None
        nativedroid_logger.info('CALLBACK: %s' % glue_callback_dict)
        return glue_callback_dict, stash_instructions

    def ANativeActivity_callback(self, project, start_state_addr):
        """
        Native activity based on 'native_activity' lib. We focus on all the callback functions in struct ANativeActivityCallbacks.
        :param project: binary file
        :param start_state_addr: ANativeActivity_onCreate address, which is the begin address of path_group.
        :return: ANativeActivity_callback dict
        """

        """
        For ANativeActivityCallbacks is a pointer element in ANativeActivity struct, we set two pointer arguments.
        0x700000 is the address of ANativeActivity, and 0x800000 is the address of ANativeActivityCallbacks.
        """
        ANativeActivityCallbacks_struct = angr.sim_type.define_struct(
            'struct ANativeActivityCallbacks {void (*onStart)(int activity); void (*onResume)(int activity); void* (*onSaveInstanceState)(int activity, int outSize); void (*onPause)(int activity); void (*onStop)(int activity); void (*onDestroy)(int activity); void (*onWindowFocusChanged)(int activity, int hasFocus); void (*onNativeWindowCreated)(int activity, int window); void (*onNativeWindowResized)(int activity, int window); void (*onNativeWindowRedrawNeeded)(int activity, int window); void (*onNativeWindowDestroyed)(int activity, int window); void (*onInputQueueCreated)(int activity, int queue); void (*onInputQueueDestroyed)(int activity, int queue); void (*onContentRectChanged)(int activity, const int rect); void (*onConfigurationChanged)(int activity); void (*onLowMemory)(int activity);}')
        activity_pointer = claripy.BVV(0x700000, 32)
        call_state = project.factory.call_state(start_state_addr, activity_pointer, add_options={angr.options.CALLLESS})
        # set activity->callbacks = 0x800000
        call_state.memory.store(0x700000, claripy.BVV(0x800000, 32), endness='Iend_LE')
        simgr = project.factory.simgr(call_state)
        limiter = angr.exploration_techniques.LengthLimiter(max_length=15)
        simgr.use_technique(limiter)
        try:
            simgr.run()
            if simgr.cut:
                state_after = simgr.cut[0]
                stash_instructions = 0
                for cut_stash in simgr.cut:
                    stash_instruction = self.count_stash_instructions(project, cut_stash)
                    stash_instructions += stash_instruction
            elif simgr.deadended:
                state_after = simgr.deadended[0]
                stash_instructions = 0
                for deadended_stash in simgr.deadended:
                    stash_instruction = self.count_stash_instructions(project, deadended_stash)
                    stash_instructions += stash_instruction
            else:
                return None, 0
            ANativeActivityCallbacks_struct_value = ANativeActivityCallbacks_struct.with_arch(project.arch).extract(
                state_after, 0x800000)._values
            nativeActivity_callback_dict = dict()
            for field in ANativeActivityCallbacks_struct_value:
                nativeActivity_callback_dict[field] = ANativeActivityCallbacks_struct_value[field].args[0]
        except Exception as e:
            nativedroid_logger.error('Exception: %s' % e)
            nativeActivity_callback_dict = None
            stash_instructions = 0
        return nativeActivity_callback_dict, stash_instructions

    @staticmethod
    def get_call_ALooper_pollAll_ins_addr(project, cfg):
        """
        Get the instruction address which call ALooper_pollAll in android_main function.
        But now, only test in arm architecture!!!

        :param cfg: Control flow graph
        :return: the instruction address which call ALooper_pollAll in android_main function.
        """

        ALooper_pollAll_plt_addr = project.loader.main_object.plt['ALooper_pollAll']
        ALooper_pollAll_node = cfg.get_any_node(ALooper_pollAll_plt_addr)
        if ALooper_pollAll_node:
            call_ALooper_pollAll_nodes = ALooper_pollAll_node.predecessors
            android_main_addr = cfg.kb.functions.function(name='android_main').addr
            call_ALooper_pollAll_ins_addr = Node
            for node in call_ALooper_pollAll_nodes:
                if node.function_address == android_main_addr:
                    call_ALooper_pollAll_ins_addr = node.instruction_addrs[-1]
            return call_ALooper_pollAll_ins_addr
        else:
            return None

    def hook_android_main_callbacks(self, project, analysis_center, entry_func_symbol):
        """
        Hook two callbacks to the android_main function.
        :param analysis_center: Analysis Center
        :param project: Project object
        :param entry_func_symbol: Entry function symbol
        :return: initial state, android_app struct, initial execution instructions number
        """
        start_state = project.factory.blank_state(addr=entry_func_symbol.rebased_addr,
                                                  add_options={angr.options.CALLLESS}, mode='fastpath')
        cfg = project.analyses.CFGAccurate(fail_fast=True, starts=[entry_func_symbol.rebased_addr],
                                           initial_state=start_state)
        cfg_instructions = self.count_cfg_instructions(cfg)
        android_main_func = cfg.kb.functions.function(name='android_main', plt=False)
        android_main_func_block_list = sorted(list(android_main_func.block_addrs_set))
        hook_addr = android_main_func_block_list[-1]
        call_ALooper_pollAll_ins_addr = self.get_call_ALooper_pollAll_ins_addr(project, cfg)
        if call_ALooper_pollAll_ins_addr:
            glue_callbacks_dict, stash_instructions = self.glue_callback(project, entry_func_symbol.rebased_addr,
                                                                         call_ALooper_pollAll_ins_addr)
        else:
            glue_callbacks_dict, stash_instructions = self.glue_callback(project, entry_func_symbol.rebased_addr,
                                                                         hook_addr)
        initial_state = project.factory.blank_state(addr=entry_func_symbol.rebased_addr)
        android_app = android_app_model.AndroidApp(project, analysis_center, initial_state)
        if glue_callbacks_dict:
            project.hook(hook_addr, CallbackHook(callbacks=glue_callbacks_dict, argument=android_app.ptr))

        return initial_state, android_app, cfg_instructions + stash_instructions

    def hook_native_activity_direct_callbacks(self, project, analysis_center, entry_func_symbol):
        """
        Hook two callbacks to the ANativeActivity_onCreate function.
        :param analysis_center: Analysis Center
        :param project: Project object
        :param entry_func_symbol: Entry function symbol
        :return: initial state, ANativeActivity struct, initial execution instructions
        """
        start_state = project.factory.blank_state(addr=entry_func_symbol.rebased_addr,
                                                  add_options={angr.options.CALLLESS}, mode='fastpath')
        cfg = project.analyses.CFGAccurate(fail_fast=True, starts=[entry_func_symbol.rebased_addr],
                                           initial_state=start_state)
        cfg_instructions = self.count_cfg_instructions(cfg)
        entry_func = cfg.kb.functions.function(name=entry_func_symbol.name, plt=False)
        entry_func_block_list = sorted(list(entry_func.block_addrs_set))
        hook_addr = entry_func_block_list[-1]
        callbacks, stash_instructions = self.ANativeActivity_callback(project, entry_func_symbol.rebased_addr)
        # nativedroid_logger.info('CALLBACKS:\n%s' % callbacks)
        initial_state = project.factory.blank_state(addr=entry_func_symbol.rebased_addr)
        activity = ANativeActivity(project, analysis_center, initial_state)
        project.hook(hook_addr, CallbackHook(callbacks=callbacks, argument=activity.ptr))
        return initial_state, activity, cfg_instructions + stash_instructions
