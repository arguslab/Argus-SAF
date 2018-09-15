import re


class SourceAndSinkManager(object):
    """
    This class is used to identify source points and sink points within given CFG.
    It will load the source and sink specifications from a sas_file with following format line by line:
    e.g., __android_log_print LOG|SENSITIVE_DATA -> _SINK_ 1|2|3
    means arg 1,2,3 of __android_log_print is the sink points if the taint_tag contains LOG or SENSITIVE_DATA.
    No arg specified means any arg could be the sink points. (Try up to 10.)
    No tait_tag specified means any tainted data could be matched.

    :param str sas_file: file path.
    """

    def __init__(self, sas_file):
        self._sources = {}
        self._sinks = {}
        self._parse(sas_file)

    #
    # Private methods.
    #
    def _parse(self, sas_file):
        """

        :param str sas_file:
        :return:
        """
        #                         1            2                   3            4
        prog = re.compile("([^\\s]+)\\s+([^\\s]+)?\\s*->\\s+([^\\s]+)\\s*([^\\s]+)?\\s*")
        for line in open(sas_file, 'r'):
            m = prog.match(line)
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

    def is_source(self, fn):
        return fn.name in self._sources

    def is_sink(self, fn):
        return fn.name in self._sinks

    def get_source_tags(self, fn):
        return self._sources.get(fn.name)

    def get_sink_tags(self, fn):
        return self._sinks.get(fn.name)
