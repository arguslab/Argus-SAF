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
        self.assertEqual('Lcom/moon/king/PluginSdk;.nativeSayTest:(Ljava/lang/String;[BI)Ljava/lang/String; -> _SINK_ 1',
                         taint_analysis_report)
        self.assertEqual('`Lcom/moon/king/PluginSdk;.nativeSayTest:(Ljava/lang/String;[BI)Ljava/lang/String;`:\n;',
                         safsu_report)

    def testGumen(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'MalwareLibs/Gumen/libsdkutils.so')
        jni_method_name = 'Java_com_umeng_adutils_SdkUtils_stringFromJNI'
        jni_method_signature = 'Lcom/umeng/adutils/SdkUtils;.stringFromJNI:(Landroid/app/PendingIntent;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;'
        jni_method_arguments = 'android.app.PendingIntent,java.lang.String,java.lang.String'
        taint_analysis_report, safsu_report, total_instructions = gen_summary(None, so_file, jni_method_name,
                                                                              jni_method_signature,
                                                                              jni_method_arguments,
                                                                              native_ss_file, java_ss_file)
        self.assertEqual('Lcom/umeng/adutils/SdkUtils;.stringFromJNI:(Landroid/app/PendingIntent;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String; -> _SINK_ 2',
                         taint_analysis_report)
        self.assertEqual('`Lcom/umeng/adutils/SdkUtils;.stringFromJNI:(Landroid/app/PendingIntent;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;`:\n  ret = "Hello from JNI4!"@~\n;',
                         safsu_report)

    def testOgel(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'MalwareLibs/Ogel/libsun.so')
        jni_method_name = 'Java_com_googlle_cn_ni_u'
        jni_method_signature = 'Lcom/googlle/cn/ni;.u:(I)Ljava/lang/String;'
        jni_method_arguments = 'int'
        taint_analysis_report, safsu_report, total_instructions = gen_summary(None, so_file, jni_method_name,
                                                                              jni_method_signature,
                                                                              jni_method_arguments,
                                                                              native_ss_file, java_ss_file)
        self.assertEqual('Lcom/googlle/cn/ni;.u:(I)Ljava/lang/String; -> _SOURCE_',
                         taint_analysis_report)
        self.assertEqual('`Lcom/googlle/cn/ni;.u:(I)Ljava/lang/String;`:\n  ret = "/athena/sqjymapiaz05.jsp?lsbtm"@~\n;',
                         safsu_report)

    def testUpdtKiller(self):
        so_file = pkg_resources.resource_filename('nativedroid.testdata',
                                                  'MalwareLibs/UpdtKiller/libuserdata.so')
        jni_method_name = 'Java_com_jnyl_lanucher2_update_UserData_GetNumber'
        jni_method_signature = 'Lcom/jnyl/lanucher2/update/UserData;.GetNumber:()Ljava/lang/String;'
        jni_method_arguments = ''
        taint_analysis_report, safsu_report, total_instructions = gen_summary(None, so_file, jni_method_name,
                                                                              jni_method_signature,
                                                                              jni_method_arguments,
                                                                              native_ss_file, java_ss_file)
        self.assertEqual('Lcom/jnyl/lanucher2/update/UserData;.GetNumber:()Ljava/lang/String; -> _SOURCE_',
                         taint_analysis_report)
        self.assertEqual('`Lcom/jnyl/lanucher2/update/UserData;.GetNumber:()Ljava/lang/String;`:\n  ret = "ELF"@~\n;',
                         safsu_report)


if __name__ == '__main__':
    unittest.main()
