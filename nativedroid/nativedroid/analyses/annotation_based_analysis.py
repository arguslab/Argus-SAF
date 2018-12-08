import copy
from cStringIO import StringIO

from nativedroid.analyses.resolver.annotation import *
from nativedroid.analyses.resolver.armel_resolver import ArmelResolver
from nativedroid.analyses.resolver.jni.jni_helper import *
from nativedroid.analyses.resolver.model.__android_log_print import *
from nativedroid.protobuf.jnsaf_grpc_pb2 import *

__author__ = "Xingwei Lin, Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"

nativedroid_logger = logging.getLogger('AnnotationBasedAnalysis')
nativedroid_logger.setLevel(logging.INFO)

annotation_location = {
    'from_reflection_call': '~',
    'from_native': '~',
    'from_class': '~'
}


class AnnotationBasedAnalysis(angr.Analysis):
    """
    This class performs taint analysis based upon angr's annotation technique.
    """

    def __init__(self, analysis_center, jni_method_addr, jni_method_arguments, is_native_pure, native_pure_info=None):
        """
        init

        :param AnalysisCenter analysis_center:
        :param str jni_method_addr: address of jni method
        :param str jni_method_arguments:
        :param list is_native_pure: whether it is pure native and android_main type or direct type.
        :param Object native_pure_info: initial SimState and native pure argument
        """
        if self.project.arch.name is 'ARMEL':
            self._resolver = ArmelResolver(self.project, analysis_center)
        else:
            raise ValueError('Unsupported architecture: %d' % self.project.arch.name)
        self._hook_system_calls()
        self._analysis_center = analysis_center
        self._jni_method_signature = analysis_center.get_signature()
        self._jni_method_addr = jni_method_addr
        if is_native_pure:
            self._state = self._resolver.prepare_native_pure_state(native_pure_info)
            self._arguments_summary = None
        else:
            self._state, self._arguments_summary = self._resolver.prepare_initial_state(jni_method_arguments)

        if is_native_pure:
            self.cfg = self.project.analyses.CFGAccurate(fail_fast=True, starts=[self._jni_method_addr],
                                                         initial_state=self._state, context_sensitivity_level=1,
                                                         keep_state=True, normalize=True, call_depth=5)
        else:
            self.cfg = self.project.analyses.CFGAccurate(fail_fast=True, starts=[self._jni_method_addr],
                                                         initial_state=self._state, context_sensitivity_level=1,
                                                         keep_state=True, normalize=True, call_depth=5)

    def _hook_system_calls(self):
        if '__android_log_print' in self.project.loader.main_object.imports:
            self.project.hook_symbol('__android_log_print', AndroidLogPrint(), replace=True)

    def count_cfg_instructions(self):
        """
        Count instructions size from CFG.

        :return: Instructions size
        :rtype: int
        """
        total_instructions = 0
        for func_addr, func in self.cfg.kb.functions.iteritems():
            func_instructions = 0
            # print func.name
            for block in func.blocks:
                block_instructions = len(block.instruction_addrs)
                # print block, block_instructions
                func_instructions += block_instructions
            total_instructions += func_instructions
        # print('Total INS: %d' % total_instructions)
        return total_instructions

    def _collect_taint_sources(self):
        """
        Collect source nodes from CFG.

        :param: jni_method_signature: method signature
        :return: A dictionary contains source nodes with its source tags (positions, taint_tags).
        :rtype: list
        """
        sources_annotation = set()
        if self._arguments_summary:
            for _, arg_summary in self._arguments_summary.iteritems():
                for annotation in arg_summary.annotations:
                    if isinstance(annotation, JobjectAnnotation):
                        worklist = list(annotation.fields_info)
                        while worklist:
                            field_info = worklist[0]
                            worklist = worklist[1:]
                            if isinstance(field_info, JobjectAnnotation):
                                if field_info.taint_info['is_taint'] and \
                                        field_info.taint_info['taint_type'][0] == '_SOURCE_' and \
                                        '_ARGUMENT_' not in field_info.taint_info['taint_type'][1]:
                                    sources_annotation.add(annotation)
                                else:
                                    worklist.extend(field_info.fields_info)
        if not self._jni_method_signature.endswith(")V"):
            for node in self.cfg.nodes():
                if not node.is_simprocedure and \
                        node.block.vex.jumpkind == 'Ijk_Ret' and \
                        node.function_address == self._jni_method_addr:
                    for final_state in node.final_states:
                        return_value = final_state.regs.r0
                        for annotation in return_value.annotations:
                            if isinstance(annotation, JobjectAnnotation):
                                if annotation.taint_info['is_taint'] and \
                                        annotation.taint_info['taint_type'][0] == '_SOURCE_' and \
                                        '_ARGUMENT_' not in annotation.taint_info['taint_type'][1]:
                                    sources_annotation.add(annotation)
        return sources_annotation

    def _collect_taint_sinks(self):
        """
        Collect sink nodes from CFG.

        :return: A dictionary contains sink nodes with its sink tags (positions, taint_tags).
        :rtype: dict
        """
        sink_nodes = {}
        sink_annotations = set()
        for node in self.cfg.nodes():
            if node.is_simprocedure and node.name.startswith('Call'):
                for final_state in node.final_states:
                    regs = [final_state.regs.r0,
                            final_state.regs.r1,
                            final_state.regs.r2,
                            final_state.regs.r3,
                            final_state.regs.r4,
                            final_state.regs.r5,
                            final_state.regs.r6,
                            final_state.regs.r7,
                            final_state.regs.r8,
                            final_state.regs.r9,
                            final_state.regs.r10]
                    for reg in regs:
                        # node_return_value = final_state.regs.r0
                        for annotation in reg.annotations:
                            if isinstance(annotation, JobjectAnnotation):
                                if annotation.taint_info['is_taint'] and \
                                        annotation.taint_info['taint_type'][0] == '_SINK_':
                                    sink_annotations.add(annotation)
            fn = self.cfg.project.kb.functions.get(node.addr)
            if fn:
                ssm = self._analysis_center.get_source_sink_manager()
                if ssm.is_sink(fn.name):
                    sink_tag = ssm.get_sink_tags(fn.name)
                    sink_nodes[node] = sink_tag
        for sink, (positions, tags) in sink_nodes.iteritems():
            input_state = sink.input_state
            final_states = sink.final_states
            args = self._resolver.get_taint_args(input_state, final_states, positions, tags)
            if args:
                nativedroid_logger.debug('tainted: %s, belong_obj: %s' % (args, sink.final_states[0].regs.r0))
                for arg in args:
                    for annotation in arg.annotations:
                        sink_annotation = copy.deepcopy(annotation)
                        sink_annotation.taint_info['taint_type'][0] = '_SINK_'
                        if annotation.taint_info['is_taint'] and \
                                annotation.taint_info['taint_type'] == ['_SOURCE_', '_API_']:
                            sink_annotation.taint_info['taint_type'][1] = '_SOURCE_'
                        sink_annotations.add(sink_annotation)
        annotations = set()
        for annotation in sink_annotations:
            if annotation.taint_info['is_taint'] and annotation.taint_info['taint_type'][1] == '_SOURCE_':
                nativedroid_logger.info('Found taint in function %s.', self._jni_method_signature)
                jnsaf_client = self._analysis_center.get_jnsaf_client()
                if jnsaf_client:
                    request = RegisterTaintRequest(
                        apk_digest=jnsaf_client.apk_digest,
                        signature=self._analysis_center.get_signature(),
                        source_kind=annotation.taint_info['source_kind'],
                        sink_kind=annotation.taint_info['sink_kind'])
                    response = jnsaf_client.RegisterTaint(request)
                    if response.status:
                        nativedroid_logger.info('Registered %s as taint.', self._jni_method_signature)
            else:
                annotations.add(annotation)
        return annotations

    def gen_taint_analysis_report(self, sources, sinks):
        """
        Generate the taint analysis report
        :param sources: Sources annotation
        :param sinks: Sinks annotation
        :return: taint analysis report
        """
        report_file = StringIO()
        if sinks:
            report_file.write(self._jni_method_signature)
            report_file.write(' -> _SINK_ ')
            args = set([])
            for sink_annotation in sinks:
                if sink_annotation.array_info['is_element']:
                    if sink_annotation.array_info['base_annotation'].source.startswith('arg'):
                        arg_index = \
                            re.split('arg|_', sink_annotation.array_info['base_annotation'].source)[1]
                        sink_location = arg_index
                        args.add(str(sink_location))
                else:
                    taint_field_name = ''
                    anno = sink_annotation
                    while anno:
                        if anno.field_info['is_field']:
                            taint_field_name = '.' + anno.field_info['field_name'] + taint_field_name
                        if anno.taint_info['is_taint'] and anno.source and anno.source.startswith('arg'):
                            args.add(anno.source.split('arg')[-1] + taint_field_name)
                            break
                        anno = anno.field_info['base_annotation']
            report_file.write('|'.join(args))
            report_file.write('\n')
        if sources:
            report_file.write(self._jni_method_signature)
            report_file.write(' -> _SOURCE_ ')
            for source_annotation in sources:
                if isinstance(source_annotation, JobjectAnnotation) and source_annotation.source.startswith('arg'):
                    source_location = source_annotation.source
                    taint_field_name = ''
                    worklist = list(source_annotation.fields_info)
                    while worklist:
                        field_info = worklist[0]
                        worklist = worklist[1:]
                        if field_info.taint_info['is_taint'] and \
                                '_ARGUMENT_' not in field_info.taint_info['taint_type'][1]:
                            taint_field_name += '.' + field_info.field_info['field_name']
                            break
                        elif isinstance(field_info, JobjectAnnotation):
                            taint_field_name += '.' + field_info.field_info['field_name']
                            worklist.extend(field_info.fields_info)
                    if taint_field_name:
                        report_file.write(source_location.split('arg')[-1] + taint_field_name)
        return report_file.getvalue().strip()

    def gen_saf_summary_report(self):
        """
        Generate SAF summary report
        :return: summary report
        """
        args_safsu = dict()
        rets_safsu = list()
        if self._arguments_summary:
            for arg_index, arg_summary in self._arguments_summary.iteritems():
                arg_safsu = dict()
                for annotation in arg_summary.annotations:
                    if isinstance(annotation, JobjectAnnotation) and annotation.fields_info:
                        for field_info in annotation.fields_info:
                            field_name = field_info.field_info['field_name']
                            field_type = field_info.obj_type.replace('/', '.')
                            field_locations = list()
                            if field_info.source in annotation_location:
                                field_location = annotation_location[field_info.source]
                                field_locations.append(field_location)
                            elif field_info.source.startswith('arg'):
                                field_location = field_info.heap
                                field_locations.append(field_location)
                            arg_safsu[field_name] = (field_type, field_locations)
                args_safsu[arg_index] = arg_safsu
        return_nodes = list()
        for node in self.cfg.nodes():
            if not node.is_simprocedure:
                if node.block.vex.jumpkind == 'Ijk_Ret' and node.function_address == self._jni_method_addr:
                    return_nodes.append(node)
        if not self._jni_method_signature.endswith(")V"):
            for return_node in return_nodes:
                for final_state in return_node.final_states:
                    return_value = final_state.regs.r0
                    for annotation in return_value.annotations:
                        if isinstance(annotation, JstringAnnotation):
                            # ret_type = annotation.primitive_type.split('L')[-1].replace('/', '.')
                            ret_type = 'java.lang.String'
                            ret_location = annotation_location[annotation.source]
                            ret_value = annotation.value
                            if ret_value is not None:
                                ret_safsu = '  ret = "' + ret_value + '"@' + ret_location
                            else:
                                ret_safsu = '  ret = ' + ret_type + '@' + ret_location
                            rets_safsu.append(ret_safsu)
                        elif isinstance(annotation, JobjectAnnotation):
                            if annotation.heap:
                                ret_value = annotation.heap
                                ret_safsu = '  ret = ' + ret_value
                                rets_safsu.append(ret_safsu)
                            else:
                                ret_type = annotation.obj_type.replace('/', '.')
                                ret_location = annotation_location[annotation.source]
                                ret_safsu = '  ret = ' + ret_type + '@' + ret_location
                                rets_safsu.append(ret_safsu)
        report_file = StringIO()
        report_file.write('`' + self._jni_method_signature + '`:' + '\n')
        if args_safsu:
            for arg_index, fields_safsu in args_safsu.iteritems():
                arg_index = 'arg:' + str(re.split('arg|_', arg_index)[1])
                for field_name, field_su in fields_safsu.iteritems():
                    field_type = field_su[0]
                    field_locations = field_su[1]
                    if field_locations[0] == '~':
                        field_safsu = arg_index + '.' + field_name + ' = ' + field_type + '@' + field_locations[0]
                    else:
                        field_safsu = arg_index + '.' + field_name + ' = ' + field_locations[0]
                    report_file.write('  ' + field_safsu.strip() + '\n')
        if rets_safsu:
            for ret_safsu in rets_safsu:
                report_file.write(ret_safsu + '\n')
        report_file.write(';\n')
        return report_file.getvalue().strip()

    def run(self):
        """
        run the analysis.
        :return:
        """
        sources = self._collect_taint_sources()
        sinks = self._collect_taint_sinks()
        return sources, sinks
