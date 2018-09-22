from nativedroid.analyses.resolver.taint_resolver import TaintResolver
from nativedroid.analyses.resolver.model.android_app_model import *
from nativedroid.analyses.resolver.model.anativeactivity_model import ANativeActivity

__author__ = "Xingwei Lin"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "EPL v1.0"


class X86Resolver(TaintResolver):
    """
    Taint solutions for x86.
    """

    def prepare_initial_state(self, arguments):
        """
        Prepare initial state for CFGAccurate.

        :param str arguments: Arguments (with taint flags) need to put to the state
        :return: Initial state and arguments summary
        :rtype: angr.sim_type.SimState and dict
        """
        arguments = arguments.split(',')
        if len(arguments) == 1 and arguments[0] == '':
            arguments = list()

        state = self._project.factory.blank_state(mode="fastpath")

        arguments_summary = dict()
        arguments_native = list()
        for idx, argument_type in enumerate(arguments):
            argument_name = 'arg' + str(idx + 1)
            if argument_type == 'long' or argument_type == 'double':
                argument_type_l = argument_type + '_l'
                argument_name_l = argument_name + '_l'
                argument_type_h = argument_type + '_h'
                argument_name_h = argument_name + '_h'
                arguments_native.append([argument_name_l, argument_type_l])
                arguments_native.append([argument_name_h, argument_type_h])
            else:
                arguments_native.append([argument_name, argument_type])
        for idx, argument in enumerate(reversed(arguments_native)):
            argument_name = argument[0]
            argument_type = argument[1]
            argument_annotation = JobjectAnnotation(source=argument_name, obj_type=argument_type, fields_info=list())
            typ = get_type(self._project, argument_type)
            typ_size = get_type_size(self._project, argument_type)
            data = claripy.BVV(typ.ptr, typ_size)
            argument_annotation.taint_info['taint_type'] = ['_SOURCE_', '_ARGUMENT_']
            argument_annotation.taint_info['taint_info'] = ['SENSITIVE_INFO']
            data = data.annotate(argument_annotation)
            state.stack_push(data)
            arguments_summary[argument_name] = data

        env = JNINativeInterface(self._project)
        this_obj = JObject(self._project)
        state.stack_push(claripy.BVV(this_obj.ptr, self._project.arch.bits))
        state.stack_push(claripy.BVV(env.ptr, self._project.arch.bits))
        state.stack_push(claripy.BVV(0x0, self._project.arch.bits))
        self._project.hook(0x0, angr.SIM_PROCEDURES['stubs']['PathTerminator']())

        return state, arguments_summary

    def prepare_native_pure_state(self, native_pure_info, other_arguments=None):
        """
        Prepare native pure initial state for CFGAccurate.

        :param Object native_pure_info: initial SimState and native pure argument
        :param list other_arguments: Arguments (with taint flags) need to put to the state.
        :return: Initial state
        :rtype: angr.sim_type.SimState
        """

        state = native_pure_info[0]
        native_pure_argument = native_pure_info[1]
        if type(native_pure_argument) is AndroidApp:
            state.stack_push(claripy.BVV(native_pure_argument.ptr, self._project.arch.bits))
            state.stack_push(claripy.BVV(0x0, self._project.arch.bits))
            self._project.hook(0x0, angr.SIM_PROCEDURES['stubs']['PathTerminator']())
        elif type(native_pure_argument) is ANativeActivity:
            saved_state_size = JInt(self._project)
            saved_state = JObject(self._project)
            state.stack_push(claripy.BVV(saved_state_size.ptr, self._project.arch.bits / 4))
            state.stack_push(claripy.BVV(saved_state.ptr, self._project.arch.bits))
            state.stack_push(claripy.BVV(native_pure_argument.ptr, self._project.arch.bits))
            state.stack_push(claripy.BVV(0x0, self._project.arch.bits))
            self._project.hook(0x0, angr.SIM_PROCEDURES['stubs']['PathTerminator']())
        return state

    def get_taint_args(self, input_state, final_states, positions, tags):
        """
        Get args with TaintAnnotation from given state.

        :param angr.Sim_type.SimState input_state: SimState of current program point.
        :param list final_states: Final SimStates of current point.
        :param list positions: Taint argument candidates.
        :param list tags: Taint tags.
        :return: Tainted args
        :rtype: list
        """
        # TODO x86 arch suppport.
        args = []
        size = self._project.arch.bits / 8
        for pos in positions:
            offset = pos * size
            mem = input_state.memory.load(input_state.regs.sp + offset, size, endness='Iend_LE')
            for annotation in mem.annotations:
                if type(annotation) is Annotation:
                    if TaintResolver._is_taint(annotation, tags):
                        args.append(mem)
        return args
