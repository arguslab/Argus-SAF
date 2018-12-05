import unittest
import pkg_resources
from nativedroid.analyses.nativedroid_analysis import *

native_ss_file = pkg_resources.resource_filename('nativedroid.data', 'sourceAndSinks/NativeSourcesAndSinks.txt')
java_ss_file = pkg_resources.resource_filename('nativedroid.data', 'sourceAndSinks/TaintSourcesAndSinks.txt')


class NativeDroidAnalysisTest(unittest.TestCase):
    def testTriada(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'MalwareLibs/Triada/libhellojni.so')
        jni_method_name = 'Java_com_moon_king_PluginSdk_nativeSayTest'
        jni_method_signature = 'Lcom/moon/king/PluginSdk;.nativeSayTest:(Ljava/lang/String;[BI)Ljava/lang/String;'
        jni_method_arguments = 'java.lang.String,byte[],int'
        taint_analysis_report, safsu_report, total_instructions = gen_summary(None, so_file, jni_method_name,
                                                                              jni_method_signature,
                                                                              jni_method_arguments,
                                                                              native_ss_file, java_ss_file)
        self.assertEqual('Lorg/arguslab/native_leak/MainActivity;.send:(Ljava/lang/String;)V -> _SINK_ 1',
                         taint_analysis_report)
        self.assertEqual('`Lorg/arguslab/native_leak/MainActivity;.send:(Ljava/lang/String;)V`:\n;',
                         safsu_report)


if __name__ == '__main__':
    unittest.main()
