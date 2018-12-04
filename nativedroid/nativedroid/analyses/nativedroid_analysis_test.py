import unittest
import pkg_resources
from nativedroid.analyses.nativedroid_analysis import *

native_ss_file = pkg_resources.resource_filename('nativedroid.data', 'sourceAndSinks/NativeSourcesAndSinks.txt')
java_ss_file = pkg_resources.resource_filename('nativedroid.data', 'sourceAndSinks/TaintSourcesAndSinks.txt')


class NativeDroidAnalysisTest(unittest.TestCase):
    def testLibLeak(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'NativeLibs/native_leak/lib/armeabi/libleak.so')
        jni_method_name = 'Java_org_arguslab_native_1leak_MainActivity_send'
        jni_method_signature = 'Lorg/arguslab/native_leak/MainActivity;.send:(Ljava/lang/String;)V'
        jni_method_arguments = 'org.arguslab.native_leak.MainActivity,java.lang.String'
        taint_analysis_report, safsu_report, total_instructions = gen_summary(None, so_file, jni_method_name,
                                                                              jni_method_signature,
                                                                              jni_method_arguments,
                                                                              native_ss_file, java_ss_file)
        self.assertEqual('Lorg/arguslab/native_leak/MainActivity;.send:(Ljava/lang/String;)V -> _SINK_ 1',
                         taint_analysis_report)
        self.assertEqual('`Lorg/arguslab/native_leak/MainActivity;.send:(Ljava/lang/String;)V`:\n;',
                         safsu_report)

    def testLibIntent(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'NativeLibs/icc_nativetojava/lib/armeabi/libintent.so')
        jni_method_name = 'Java_org_arguslab_icc_1nativetojava_MainActivity_sendIntent'
        jni_method_signature = 'Lorg/arguslab/icc_nativetojava/MainActivity;.sendIntent:(Ljava/lang/String;)V'
        jni_method_arguments = 'org.arguslab.icc_nativetojava.MainActivity,java.lang.String'
        taint_analysis_report, safsu_report, total_instructions = gen_summary(None, so_file, jni_method_name,
                                                                              jni_method_signature,
                                                                              jni_method_arguments,
                                                                              native_ss_file, java_ss_file)
        self.assertEqual('', taint_analysis_report)
        self.assertEqual('`Lorg/arguslab/icc_nativetojava/MainActivity;.sendIntent:(Ljava/lang/String;)V`:\n;',
                         safsu_report)

    def testLibMethodOverloading(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'NativeLibs/native_method_overloading/lib/armeabi/'
                                                  'libmethod_overloading.so')
        jni_method_name = 'Java_org_arguslab_native_1method_1overloading_MainActivity_' \
                          'send___3I_3Ljava_lang_String_2Ljava_lang_String_2D'
        jni_method_signature = 'Lorg/arguslab/native_method_overloading/MainActivity;' \
                               '.send:([I[Ljava/lang/String;Ljava/lang/String;D)V'
        jni_method_arguments = 'org.arguslab.native_method_overloading.MainActivity,' \
                               'int[],java.lang.String[],java.lang.String,double'
        taint_analysis_report, safsu_report, total_instructions = gen_summary(None, so_file, jni_method_name,
                                                                              jni_method_signature,
                                                                              jni_method_arguments,
                                                                              native_ss_file, java_ss_file)
        self.assertEqual('Lorg/arguslab/native_method_overloading/MainActivity;.'
                         'send:([I[Ljava/lang/String;Ljava/lang/String;D)V -> _SINK_ 3',
                         taint_analysis_report)
        self.assertEqual('`Lorg/arguslab/native_method_overloading/MainActivity;.'
                         'send:([I[Ljava/lang/String;Ljava/lang/String;D)V`:\n'
                         ';',
                         safsu_report)

    def testLibHeapModify(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'NativeLibs/native_heap_modify/lib/armeabi/libheap_modify.so')
        jni_method_name = 'Java_org_arguslab_native_1heap_1modify_MainActivity_heapModify'
        jni_method_signature = 'Lorg/arguslab/native_heap_modify/MainActivity;.' \
                               'heapModify:(Landroid/content/Context;Lorg/arguslab/native_heap_modify/Data;)V'
        jni_method_arguments = 'org.arguslab.native_heap_modify.MainActivity,android.content.Context,' \
                               'org.arguslab.native_heap_modify.Data'
        taint_analysis_report, safsu_report, total_instructions = gen_summary(None, so_file, jni_method_name,
                                                                              jni_method_signature,
                                                                              jni_method_arguments,
                                                                              native_ss_file, java_ss_file)
        self.assertEqual('Lorg/arguslab/native_heap_modify/MainActivity;.heapModify'
                         ':(Landroid/content/Context;Lorg/arguslab/native_heap_modify/Data;)V -> _SOURCE_ 2.str',
                         taint_analysis_report)
        self.assertEqual('`Lorg/arguslab/native_heap_modify/MainActivity;.heapModify:'
                         '(Landroid/content/Context;Lorg/arguslab/native_heap_modify/Data;)V`:\n'
                         '  arg:2.str = java.lang.String@~\n'
                         ';',
                         safsu_report)

    def testLibLeakDynamicRegister(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'NativeLibs/native_leak_dynamic_register/lib/'
                                                  'armeabi/libleak_dynamic_register.so')
        jni_method_signature = 'Lorg/arguslab/native_leak_dynamic_register/MainActivity;.send:(Ljava/lang/String;)V'
        dynamic_maps = get_dynamic_register_methods(so_file, jni_method_signature)
        jni_addr = dynamic_maps.get('send:(Ljava/lang/String;)V')
        jni_method_arguments = 'org.arguslab.native_leak_dynamic_register.MainActivity,java.lang.String'
        taint_analysis_report, safsu_report, total_instructions = gen_summary(None, so_file, jni_addr,
                                                                              jni_method_signature,
                                                                              jni_method_arguments,
                                                                              native_ss_file, java_ss_file)
        self.assertEqual('Lorg/arguslab/native_leak_dynamic_register/MainActivity;'
                         '.send:(Ljava/lang/String;)V -> _SINK_ 1',
                         taint_analysis_report)
        self.assertEqual('`Lorg/arguslab/native_leak_dynamic_register/MainActivity;.send:(Ljava/lang/String;)V`:\n'
                         ';',
                         safsu_report)

    def testLibDynamicRegisterMultiple(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'NativeLibs/native_dynamic_register_multiple/lib/'
                                                  'armeabi/libdynamic_register_multiple.so')
        jni_method_signature = 'Lorg/arguslab/native_dynamic_register_multiple/MainActivity;.send:(Ljava/lang/String;)V'
        dynamic_maps = get_dynamic_register_methods(so_file, jni_method_signature)
        jni_addr = dynamic_maps.get('send:(Ljava/lang/String;)V')
        jni_method_arguments = 'org.arguslab.native_dynamic_register_multiple.MainActivity,java.lang.String'
        taint_analysis_report, safsu_report, total_instructions = gen_summary(None, so_file, jni_addr,
                                                                              jni_method_signature,
                                                                              jni_method_arguments,
                                                                              native_ss_file, java_ss_file)
        self.assertEqual('Lorg/arguslab/native_dynamic_register_multiple/MainActivity;'
                         '.send:(Ljava/lang/String;)V -> _SINK_ 1',
                         taint_analysis_report)
        self.assertEqual('`Lorg/arguslab/native_dynamic_register_multiple/MainActivity;.send:(Ljava/lang/String;)V`:\n'
                         ';',
                         safsu_report)

    def testLibSource(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'NativeLibs/native_source/lib/armeabi/libsource.so')
        jni_method_name = 'Java_org_arguslab_native_1source_MainActivity_getImei'
        jni_method_signature = 'Lorg/arguslab/native_source/MainActivity;' \
                               '.getImei:(Landroid/content/Context;)Ljava/lang/String;'
        jni_method_arguments = 'org.arguslab.native_source.MainActivity,android.content.Context'
        taint_analysis_report, safsu_report, total_instructions = gen_summary(None, so_file, jni_method_name,
                                                                              jni_method_signature,
                                                                              jni_method_arguments,
                                                                              native_ss_file, java_ss_file)
        self.assertEqual('Lorg/arguslab/native_source/MainActivity;'
                         '.getImei:(Landroid/content/Context;)Ljava/lang/String; -> _SOURCE_',
                         taint_analysis_report)
        self.assertEqual('`Lorg/arguslab/native_source/MainActivity;'
                         '.getImei:(Landroid/content/Context;)Ljava/lang/String;`:\n'
                         '  ret = java.lang.String@~\n'
                         ';',
                         safsu_report)

    def testLibDataStringOp(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'NativeLibs/native_complexdata_stringop/lib/armeabi/libdata.so')
        jni_method_name = 'Java_org_arguslab_native_1complexdata_1stringop_MainActivity_send'
        jni_method_signature = 'Lorg/arguslab/native_complexdata_stringop/MainActivity;' \
                               '.send:(Lorg/arguslab/native_complexdata_stringop/ComplexData;)V'
        jni_method_arguments = 'org.arguslab.native_complexdata_stringop.MainActivity,' \
                               'org.arguslab.native_complexdata_stringop.ComplexData'
        taint_analysis_report, safsu_report, total_instructions = gen_summary(None, so_file, jni_method_name,
                                                                              jni_method_signature,
                                                                              jni_method_arguments,
                                                                              native_ss_file, java_ss_file)
        self.assertEqual('Lorg/arguslab/native_complexdata_stringop/MainActivity;'
                         '.send:(Lorg/arguslab/native_complexdata_stringop/ComplexData;)V -> _SINK_ 1.other',
                         taint_analysis_report)
        self.assertEqual('`Lorg/arguslab/native_complexdata_stringop/MainActivity;'
                         '.send:(Lorg/arguslab/native_complexdata_stringop/ComplexData;)V`:\n'
                         ';',
                         safsu_report)

    def testLibSetFieldFromArg(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'NativeLibs/native_set_field_from_arg/lib/'
                                                  'armeabi/libset_field_from_arg.so')
        jni_method_name = 'Java_org_arguslab_native_1set_1field_1from_1arg_MainActivity_setField'
        jni_method_signature = 'Lorg/arguslab/native_set_field_from_arg/MainActivity;' \
                               '.setField:(Lorg/arguslab/native_set_field_from_arg/ComplexData;' \
                               'Lorg/arguslab/native_set_field_from_arg/Foo;)' \
                               'Lorg/arguslab/native_set_field_from_arg/Foo;'
        jni_method_arguments = 'org.arguslab.native_set_field_from_arg.MainActivity,' \
                               'org.arguslab.native_set_field_from_arg.ComplexData,' \
                               'org.arguslab.native_set_field_from_arg.Foo'
        taint_analysis_report, safsu_report, total_instructions = gen_summary(None, so_file, jni_method_name,
                                                                              jni_method_signature,
                                                                              jni_method_arguments,
                                                                              native_ss_file, java_ss_file)
        self.assertEqual('',
                         taint_analysis_report)
        self.assertEqual('`Lorg/arguslab/native_set_field_from_arg/MainActivity;'
                         '.setField:(Lorg/arguslab/native_set_field_from_arg/ComplexData;'
                         'Lorg/arguslab/native_set_field_from_arg/Foo;)Lorg/arguslab/native_set_field_from_arg/Foo;`:\n'
                         '  arg:1.foo = arg:2\n'
                         '  ret = arg:1.foo\n'
                         ';',
                         safsu_report)

    def testLibSetFieldFromArgField(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'NativeLibs/native_set_field_from_arg_field/lib/'
                                                  'armeabi/libset_field_from_arg_field.so')
        jni_method_name = 'Java_org_arguslab_native_1set_1field_1from_1arg_1field_MainActivity_setField'
        jni_method_signature = 'Lorg/arguslab/native_set_field_from_arg_field/MainActivity;' \
                               '.setField:(Lorg/arguslab/native_set_field_from_arg_field/ComplexData;' \
                               'Lorg/arguslab/native_set_field_from_arg_field/ComplexData;)' \
                               'Lorg/arguslab/native_set_field_from_arg_field/Foo;'
        jni_method_arguments = 'org.arguslab.native_set_field_from_arg_field.MainActivity,' \
                               'org.arguslab.native_set_field_from_arg_field.ComplexData,' \
                               'org.arguslab.native_set_field_from_arg_field.ComplexData'
        taint_analysis_report, safsu_report, total_instructions = gen_summary(None, so_file, jni_method_name,
                                                                              jni_method_signature,
                                                                              jni_method_arguments,
                                                                              native_ss_file, java_ss_file)
        self.assertEqual('',
                         taint_analysis_report)
        self.assertEqual('`Lorg/arguslab/native_set_field_from_arg_field/MainActivity;'
                         '.setField:(Lorg/arguslab/native_set_field_from_arg_field/ComplexData;'
                         'Lorg/arguslab/native_set_field_from_arg_field/ComplexData;)'
                         'Lorg/arguslab/native_set_field_from_arg_field/Foo;`:\n'
                         '  arg:1.foo = arg:2.foo\n'
                         '  ret = arg:1.foo\n'
                         ';',
                         safsu_report)

    def testSetFieldFromNative(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'NativeLibs/native_set_field_from_native/lib/'
                                                  'armeabi/libset_field_from_native.so')
        jni_method_name = 'Java_org_arguslab_native_1set_1field_1from_1native_MainActivity_setField'
        jni_method_signature = 'Lorg/arguslab/native_set_field_from_native/MainActivity;' \
                               '.setField:(Lorg/arguslab/native_set_field_from_native/ComplexData;)' \
                               'Lorg/arguslab/native_set_field_from_native/Foo;'
        jni_method_arguments = 'org.arguslab.native_set_field_from_native.MainActivity,' \
                               'org.arguslab.native_set_field_from_native.ComplexData'
        taint_analysis_report, safsu_report, total_instructions = gen_summary(None, so_file, jni_method_name,
                                                                              jni_method_signature,
                                                                              jni_method_arguments,
                                                                              native_ss_file, java_ss_file)
        self.assertEqual('Lorg/arguslab/native_set_field_from_native/MainActivity;'
                         '.setField:(Lorg/arguslab/native_set_field_from_native/ComplexData;)'
                         'Lorg/arguslab/native_set_field_from_native/Foo; -> _SOURCE_ 1.foo.data',
                         taint_analysis_report)
        self.assertEqual('`Lorg/arguslab/native_set_field_from_native/MainActivity;'
                         '.setField:(Lorg/arguslab/native_set_field_from_native/ComplexData;)'
                         'Lorg/arguslab/native_set_field_from_native/Foo;`:\n'
                         '  arg:1.foo = org.arguslab.native_set_field_from_native.Foo@~\n'
                         '  ret = arg:1.foo\n'
                         ';',
                         safsu_report)

    def testLibLeakArray(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'NativeLibs/native_leak_array/lib/armeabi/libleak_array.so')
        jni_method_name = 'Java_org_arguslab_native_1leak_1array_MainActivity_send'
        jni_method_signature = 'Lorg/arguslab/native_leak_array/MainActivity;.send:([Ljava/lang/String;)V'
        jni_method_arguments = 'org.arguslab.native_leak_array.MainActivity,java.lang.String[]'
        taint_analysis_report, safsu_report, total_instructions = gen_summary(None, so_file, jni_method_name,
                                                                              jni_method_signature,
                                                                              jni_method_arguments,
                                                                              native_ss_file, java_ss_file)
        self.assertEqual('Lorg/arguslab/native_leak_array/MainActivity;.send:([Ljava/lang/String;)V -> _SINK_ 1',
                         taint_analysis_report)
        self.assertEqual('`Lorg/arguslab/native_leak_array/MainActivity;.send:([Ljava/lang/String;)V`:\n'
                         ';',
                         safsu_report)

    def testICCJavaToNativeNativeActivity(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'NativeLibs/icc_javatonative/lib/armeabi/libnative-activity.so')
        size = native_activity_analysis(None, so_file, None, native_ss_file, java_ss_file)
        self.assertEqual(534, size)

    def testNativePureNativeActivity(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'NativeLibs/native_pure/lib/armeabi/libnative-activity.so')
        size = native_activity_analysis(None, so_file, None, native_ss_file, java_ss_file)
        self.assertEqual(871, size)

    def testnativePureDirectNativeActivity(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'NativeLibs/native_pure_direct/lib/armeabi/libnative-activity.so')
        size = native_activity_analysis(None, so_file, None, native_ss_file, java_ss_file)
        self.assertEqual(868, size)

    def testNativePureDirectCustomizedNativeActivity(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'NativeLibs/native_pure_direct_customized/lib/'
                                                  'armeabi/libnative-activity.so')
        size = native_activity_analysis(None, so_file, 'NativeActivity_Entry', native_ss_file, java_ss_file)
        self.assertEqual(868, size)


if __name__ == '__main__':
    unittest.main()
