from nativedroid.analyses.resolver.taint_resolver import TaintResolver
from nativedroid.analyses.resolver.model.android_app_model import *

__author__ = "Xingwei Lin"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"


class ArmelResolver(TaintResolver):
    """
    Taint solutions for armel.
    """

    def prepare_initial_state(self, arguments):
        """
        Prepare initial state for CFGAccurate.

        :param str arguments: Arguments (with taint flags) need to put to the state.
        :return: Initial state and arguments summary
        :rtype: angr.sim_type.SimState and dict
        """
        # JNI signature arguments
        arguments = arguments.replace('.', '/').split(',')
        # arguments = arguments.split(',')
        if len(arguments) == 1 and arguments[0] == '':
            arguments = list()

        if len(arguments) > 15:
            raise ValueError("Param num is limited to 15 for armel.")

        state = self._project.factory.blank_state(mode="fastpath")
        state.regs.r0 = claripy.BVV(JNINativeInterface(self._project, self._analysis_center).ptr,
                                    self._project.arch.bits)
        # state.regs.r1 = claripy.BVV(JObject(self._project).ptr, self._project.arch.bits)
        i = 1

        arguments_summary = dict()
        arguments_native = list()
        for idx, argument_type in enumerate(arguments):
            argument_name = 'arg' + str(idx)
            if argument_type == 'long' or argument_type == 'double':
                argument_type_l = argument_type + '_l'
                argument_name_l = argument_name + '_l'
                argument_type_h = argument_type + '_h'
                argument_name_h = argument_name + '_h'
                arguments_native.append([argument_name_l, argument_type_l])
                arguments_native.append([argument_name_h, argument_type_h])
            else:
                arguments_native.append([argument_name, argument_type])
        # In armel arch, arguments are stored in two parts, registers and stack.
        reg_args = list()
        stack_args = list()
        for index, argument in enumerate(arguments_native):
            if index < 3:
                reg_args.append(argument)
            else:
                stack_args.append(argument)

        for idx, argument in enumerate(reg_args):
            argument_name = argument[0]
            argument_type = argument[1]
            typ = get_type(self._project, argument_type.replace('/', '.'))
            typ_size = get_type_size(self._project, argument_type)
            data = claripy.BVV(typ.ptr, typ_size)
            argument_annotation = construct_annotation(argument_type, argument_name)
            # argument_annotation = jobjectAnnotation(source=argument_name, obj_type=argument_type, fields_info=list())
            argument_annotation.taint_info['is_taint'] = True
            argument_annotation.taint_info['taint_type'] = ['_SOURCE_', '_ARGUMENT_']
            argument_annotation.taint_info['taint_info'] = ['SENSITIVE_INFO']
            argument_annotation.taint_info['source_kind'] = 'api_source'
            data = data.annotate(argument_annotation)
            state.regs.__setattr__('r%d' % (idx + i), data)
            # store the argument summary
            arguments_summary[argument_name] = data

        for idx, argument in enumerate(reversed(stack_args)):
            argument_name = argument[0]
            argument_type = argument[1]
            typ = get_type(self._project, argument_type.replace('/', '.'))
            typ_size = get_type_size(self._project, argument_type)
            data = claripy.BVV(typ.ptr, typ_size)
            argument_annotation = construct_annotation(argument_type, argument_name)
            # argument_annotation = jobjectAnnotation(source=argument_name, obj_type=argument_type, fields_info=list())
            argument_annotation.taint_info['is_taint'] = True
            argument_annotation.taint_info['taint_type'] = ['_SOURCE_', '_ARGUMENT_']
            argument_annotation.taint_info['taint_info'] = ['SENSITIVE_INFO']
            argument_annotation.taint_info['source_kind'] = 'api_source'
            data = data.annotate(argument_annotation)
            state.stack_push(data)
            # store the argument summary
            arguments_summary[argument_name] = data

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
        state.regs.r0 = claripy.BVV(native_pure_argument.ptr, self._project.arch.bits)

        return state

    def get_taint_args(self, input_state, final_states, positions, tags):
        """
        Get args with TaintAnnotation from given state.

        :param angr.sim_type.SimState input_state: SimState of current program point.
        :param list final_states: Final SimState of current point.
        :param list positions: Taint argument candidates.
        :param list tags: Taint tags.
        :return: Tainted args
        :rtype: list
        """

        args = []
        size = self._project.arch.bits / 8
        for final_state in final_states:
            for r0_annotation in final_state.regs.r0.annotations:
                if isinstance(r0_annotation, TaintPositionAnnotation):
                    reg_position = r0_annotation.reg_position
                    stack_position = r0_annotation.stack_position
                    reg_arg = input_state.regs.get('r%d' % reg_position)
                    for annotation in reg_arg.annotations:
                        if isinstance(annotation, JobjectAnnotation):
                            if annotation.taint_info['is_taint']:
                                # if TaintResolver._is_taint(annotation.obj_taint_position, tags):
                                args.append(reg_arg)
                    for pos in stack_position:
                        # siutable for android_main
                        offset = pos * size
                        stack_arg = input_state.memory.load(input_state.regs.sp + offset, size, endness='Iend_LE')
                        for annotation in stack_arg.annotations:
                            if isinstance(annotation, JobjectAnnotation):
                                if annotation.taint_info['is_taint']:
                                    args.append(stack_arg)
        return args
