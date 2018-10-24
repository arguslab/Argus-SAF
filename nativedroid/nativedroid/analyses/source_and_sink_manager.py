import re

__author__ = "Xingwei Lin, Fengguo Wei"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"


class SourceAndSinkManager(object):
    """
    This class is used to identify source points and sink points within given CFG.
    It will load the source and sink specifications from a sas_file with following format line by line:
    e.g., __android_log_print LOG|SENSITIVE_DATA -> _SINK_ 1|2|3
    means arg 1,2,3 of __android_log_print is the sink points if the taint_tag contains LOG or SENSITIVE_DATA.
    No arg specified means any arg could be the sink points. (Try up to 10.)
    No tait_tag specified means any tainted data could be matched.

    :param native_ss_file: Native source and sink file path
    :param java_ss_file: Java source and sink file path
    """

    def __init__(self, native_ss_file, java_ss_file):
        #                              1            2                   3            4
        self._prog = re.compile("([^\\s]+)\\s+([^\\s]+)?\\s*->\\s+([^\\s]+)\\s*([^\\s]+)?\\s*")
        self._sources = {}
        self._sinks = {}
        self._parse(native_ss_file)
        self._parse(java_ss_file)

    #
    # Private methods.
    #
    def _parse(self, sas_file):
        for line in open(sas_file, 'r'):
            self.parse_line(line)

    def parse_lines(self, lines):
        for line in lines.splitlines():
            self.parse_line(line)

    def parse_line(self, line):
        m = self._prog.match(line)
        if m:
            api_name = m.group(1)
            taint_tag_raw = m.group(2)
            taint_tags = ['TOP'] if not taint_tag_raw else taint_tag_raw.split('|')
            tag = m.group(3)
            pos_raw = m.group(4)
            positions = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] if not pos_raw else map(int, pos_raw.split('|'))
            if tag == "_SOURCE_":
                self._sources[api_name] = taint_tags
            elif tag == "_SINK_":
                self._sinks[api_name] = (positions, taint_tags)

    def is_source(self, name):
        return name in self._sources

    def is_sink(self, name):
        return name in self._sinks

    def get_source_tags(self, name):
        return self._sources.get(name)

    def get_sink_tags(self, name):
        return self._sinks.get(name)
