package org.argus.jnsaf.analysis

import org.argus.jawa.core.{DefaultReporter, Signature}
import org.argus.jnsaf.serialization.DataCommunicator
import org.scalatest.{FlatSpec, Matchers}

import scala.language.implicitConversions

class NativeDroidBridgeTest extends FlatSpec with Matchers {
  implicit def string2file(s: String): TestSig = new TestSig(s)

  "Lorg/arguslab/native_leak/MainActivity;.send:(Ljava/lang/String;)V" in "/NativeFlowBench/NativeLibs/native_leak/armeabi/libleak.so" genSummary(
    "Lorg/arguslab/native_leak/MainActivity;.send:(Ljava/lang/String;)V -> _SINK_ 1",
    """`Lorg/arguslab/native_leak/MainActivity;.send:(Ljava/lang/String;)V`:
      |;
    """.stripMargin.trim
  )

  "Lorg/arguslab/native_heap_modify/MainActivity;.heapModify:(Landroid/content/Context;Lorg/arguslab/native_heap_modify/Data;)V" in "/NativeFlowBench/NativeLibs/native_heap_modify/armeabi/libheap_modify.so" genSummary(
    "Lorg/arguslab/native_heap_modify/MainActivity;.heapModify:(Landroid/content/Context;Lorg/arguslab/native_heap_modify/Data;)V -> _SOURCE_ 2.str",
    """`Lorg/arguslab/native_heap_modify/MainActivity;.heapModify:(Landroid/content/Context;Lorg/arguslab/native_heap_modify/Data;)V`:
      |  arg:2.str = java.lang.String@~
      |;
    """.stripMargin.trim
  )

  "Lorg/arguslab/native_leak_dynamic_register/MainActivity;.send:(Ljava/lang/String;)V" in "/NativeFlowBench/NativeLibs/native_leak_dynamic_register/armeabi/libleak_dynamic_register.so" genSummary(
    "Lorg/arguslab/native_leak_dynamic_register/MainActivity;.send:(Ljava/lang/String;)V -> _SINK_ 1",
    """`Lorg/arguslab/native_leak_dynamic_register/MainActivity;.send:(Ljava/lang/String;)V`:
      |;
    """.stripMargin.trim
  )

  "Lorg/arguslab/native_dynamic_register_multiple/MainActivity;.send:(Ljava/lang/String;)V" in "/NativeFlowBench/NativeLibs/native_dynamic_register_multiple/armeabi/libdynamic_register_multiple.so" genSummary(
    "Lorg/arguslab/native_dynamic_register_multiple/MainActivity;.send:(Ljava/lang/String;)V -> _SINK_ 1",
    """`Lorg/arguslab/native_dynamic_register_multiple/MainActivity;.send:(Ljava/lang/String;)V`:
      |;
    """.stripMargin.trim
  )

  "Lorg/arguslab/native_source/MainActivity;.getImei:(Landroid/content/Context;)Ljava/lang/String;" in "/NativeFlowBench/NativeLibs/native_source/armeabi/libsource.so" genSummary(
    "Lorg/arguslab/native_source/MainActivity;.getImei:(Landroid/content/Context;)Ljava/lang/String; -> _SOURCE_ ",
    """`Lorg/arguslab/native_source/MainActivity;.getImei:(Landroid/content/Context;)Ljava/lang/String;`:
      |  ret = java.lang.String@~
      |;
    """.stripMargin.trim
  )

  "Lorg/arguslab/native_complexdata/MainActivity;.send:(Lorg/arguslab/native_complexdata/ComplexData;)V" in "/NativeFlowBench/NativeLibs/native_complexdata/armeabi/libdata.so" genSummary(
    "Lorg/arguslab/native_complexdata/MainActivity;.send:(Lorg/arguslab/native_complexdata/ComplexData;)V -> _SINK_ ~",
    """`Lorg/arguslab/native_complexdata/MainActivity;.send:(Lorg/arguslab/native_complexdata/ComplexData;)V`:
      |;
    """.stripMargin.trim
  )

  "Lorg/arguslab/native_set_field_from_arg/MainActivity;.setField:(Lorg/arguslab/native_set_field_from_arg/ComplexData;Lorg/arguslab/native_set_field_from_arg/Foo;)Lorg/arguslab/native_set_field_from_arg/Foo;" in "/NativeFlowBench/NativeLibs/native_set_field_from_arg/armeabi/libset_field_from_arg.so" genSummary(
    "Lorg/arguslab/native_set_field_from_arg/MainActivity;.setField:(Lorg/arguslab/native_set_field_from_arg/ComplexData;Lorg/arguslab/native_set_field_from_arg/Foo;)Lorg/arguslab/native_set_field_from_arg/Foo;",
    """`Lorg/arguslab/native_set_field_from_arg/MainActivity;.setField:(Lorg/arguslab/native_set_field_from_arg/ComplexData;Lorg/arguslab/native_set_field_from_arg/Foo;)Lorg/arguslab/native_set_field_from_arg/Foo;`:
      |  arg:1.foo = org.arguslab.native_set_field_from_arg.Foo@arg:2
      |  ret = org.arguslab.native_set_field_from_arg.Foo@arg:1.foo
      |;
    """.stripMargin.trim
  )

  "Lorg/arguslab/native_set_field_from_arg_field/MainActivity;.setField:(Lorg/arguslab/native_set_field_from_arg_field/ComplexData;Lorg/arguslab/native_set_field_from_arg_field/ComplexData;)Lorg/arguslab/native_set_field_from_arg_field/Foo;" in "/NativeFlowBench/NativeLibs/native_set_field_from_arg_field/armeabi/libset_field_from_arg_field.so" genSummary(
    "Lorg/arguslab/native_set_field_from_arg_field/MainActivity;.setField:(Lorg/arguslab/native_set_field_from_arg_field/ComplexData;Lorg/arguslab/native_set_field_from_arg_field/ComplexData;)Lorg/arguslab/native_set_field_from_arg_field/Foo; -> _SOURCE_ 1.foo",
    """`Lorg/arguslab/native_set_field_from_arg_field/MainActivity;.setField:(Lorg/arguslab/native_set_field_from_arg_field/ComplexData;Lorg/arguslab/native_set_field_from_arg_field/ComplexData;)Lorg/arguslab/native_set_field_from_arg_field/Foo;`:
      |  arg:1.foo = org.arguslab.native_set_field_from_arg_field.Foo@arg:2.foo
      |  ret = org.arguslab.native_set_field_from_arg_field.Foo@arg:1.foo
      |;
    """.stripMargin.trim
  )

  "Lorg/arguslab/native_set_field_from_native/MainActivity;.setField:(Lorg/arguslab/native_set_field_from_native/ComplexData;)Lorg/arguslab/native_set_field_from_native/Foo;" in "/NativeFlowBench/NativeLibs/native_set_field_from_native/armeabi/libset_field_from_native.so" genSummary(
    "Lorg/arguslab/native_set_field_from_native/MainActivity;.setField:(Lorg/arguslab/native_set_field_from_native/ComplexData;)Lorg/arguslab/native_set_field_from_native/Foo; -> _SOURCE_ 1.foo.data",
    """`Lorg/arguslab/native_set_field_from_native/MainActivity;.setField:(Lorg/arguslab/native_set_field_from_native/ComplexData;)Lorg/arguslab/native_set_field_from_native/Foo;`:
      |  arg:1.foo = org.arguslab.native_set_field_from_native.Foo@~
      |  ret = org.arguslab.native_set_field_from_native.Foo@arg:1.foo
      |;
    """.stripMargin.trim
  )

  "Lorg/arguslab/native_method_overloading/MainActivity;.send:([I[Ljava/lang/String;Ljava/lang/String;D)V" in "/NativeFlowBench/NativeLibs/native_method_overloading/armeabi/libmethod_overloading.so" overload() genSummary(
    "Lorg/arguslab/native_method_overloading/MainActivity;.send:([I[Ljava/lang/String;Ljava/lang/String;D)V -> _SINK_ 3",
    """`Lorg/arguslab/native_method_overloading/MainActivity;.send:([I[Ljava/lang/String;Ljava/lang/String;D)V`:
      |;
    """.stripMargin.trim
  )

  class TestSig(sig: String) {
    private var ol: Boolean = false
    private val signature: Signature = new Signature(sig)
    private var soFile: String = _

    def in(soFile: String): TestSig = {
      this.soFile = getClass.getResource(soFile).getPath
      this
    }

    def overload(): TestSig = {
      this.ol = true
      this
    }

    def genSummary(expTaint: String, expSafsu: String): Unit = {
      sig should "produce summary as expected" in {
        System.getProperties.setProperty("jpy.config", "jpy/jpyconfig.properties")

        val bridge = new NativeDroidBridge(new DefaultReporter)
        bridge.open()

        var res: (String, String) = ("", "")
        try {
          res = bridge.genSummary(soFile, NativeMethodHandler.getJNIFunctionName(signature, ol), signature, DataCommunicator.serializeParameters(signature))
        } catch {
          case e: Throwable =>
            e.printStackTrace()
        }
        assert(res._1 == expTaint && res._2 == expSafsu)
      }
    }
  }

}
