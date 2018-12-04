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

    _ICC_SOURCE_METHODS = [
        'Landroid/content/Intent;.getStringArrayExtra:(Ljava/lang/String;)[Ljava/lang/String;',
        'Landroid/content/Intent;.getStringArrayListExtra:(Ljava/lang/String;)Ljava/util/ArrayList;'
        'Landroid/content/Intent;.getStringExtra:(Ljava/lang/String;)Ljava/lang/String;'
    ]

    _ICC_SINK_METHODS = [
        'Landroid/content/Context;startService:(Landroid/content/Intent;)Landroid/content/ComponentName;',
        'bindService:(Landroid/content/Intent;Landroid/content/ServiceConnection;I)Z',
        'startActivity:(Landroid/content/Intent;)V',
        'startActivity:(Landroid/content/Intent;Landroid/os/Bundle;)V',
        'startActivityForResult:(Landroid/content/Intent;I)V',
        'startActivityForResult:(Landroid/content/Intent;ILandroid/os/Bundle;)V',
        'sendBroadcast:(Landroid/content/Intent;)V',
        'sendBroadcast:(Landroid/content/Intent;Ljava/lang/String;)V',
        'sendBroadcastAsUser:(Landroid/content/Intent;Landroid/os/UserHandle;)V',
        'sendBroadcastAsUser:(Landroid/content/Intent;Landroid/os/UserHandle;Ljava/lang/String;)V',
        'sendOrderedBroadcast:(Landroid/content/Intent;Ljava/lang/String;)V',
        'sendOrderedBroadcast:(Landroid/content/Intent;Ljava/lang/String;Landroid/content/BroadcastReceiver;'
        'Landroid/os/Handler;ILjava/lang/String;Landroid/os/Bundle;)V',
        'sendOrderedBroadcastAsUser:(Landroid/content/Intent;Landroid/os/UserHandle;Ljava/lang/String;'
        'Landroid/content/BroadcastReceiver;Landroid/os/Handler;ILjava/lang/String;Landroid/os/Bundle;)V',
        'sendStickyBroadcast:(Landroid/content/Intent;)V',
        'sendStickyBroadcastAsUser:(Landroid/content/Intent;Landroid/os/UserHandle;)V',
        'sendStickyOrderedBroadcast:(Landroid/content/Intent;Landroid/content/BroadcastReceiver;'
        'Landroid/os/Handler;ILjava/lang/String;Landroid/os/Bundle;)V',
        'sendStickyOrderedBroadcastAsUser:(Landroid/content/Intent;Landroid/os/UserHandle;'
        'Landroid/content/BroadcastReceiver;Landroid/os/Handler;ILjava/lang/String;Landroid/os/Bundle;)V'
    ]

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

    def get_source_kind(self, name):
        return 'icc_source' if name in self._ICC_SOURCE_METHODS else 'api_source'

    def get_sink_kind(self, name):
        return 'icc_sink' if name in self._ICC_SINK_METHODS else 'api_sink'
