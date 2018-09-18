package org.argus.jnsaf.taint

import hu.ssh.progressbar.ConsoleProgressBar
import org.argus.amandroid.alir.pta.model.AndroidModelCallHandler
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.alir.taintAnalysis.{AndroidSourceAndSinkManager, DataLeakageAndroidSourceAndSinkManager}
import org.argus.amandroid.core.{AndroidGlobalConfig, ApkGlobal}
import org.argus.jawa.alir.reachability.SignatureBasedCallGraph
import org.argus.jawa.core.util._
import org.argus.jawa.core.{JawaType, Reporter}
import org.argus.jawa.summary.store.TaintStore
import org.argus.jawa.summary.wu.{TaintSummary, TaintWu, WorkUnit}
import org.argus.jawa.summary.{BottomUpSummaryGenerator, SummaryManager}
import org.argus.jnsaf.analysis.NativeMethodHandler
import org.argus.jnsaf.summary.wu.NativeTaintWU

/**
  * Created by fgwei on 1/26/18.
  */
class JNTaintAnalysis(apk: ApkGlobal, native_handler: NativeMethodHandler, reporter: Reporter) {
  val provider: AndroidSummaryProvider = new AndroidSummaryProvider(apk)
  val handler: AndroidModelCallHandler = new AndroidModelCallHandler
  val ssm: AndroidSourceAndSinkManager = new DataLeakageAndroidSourceAndSinkManager(AndroidGlobalConfig.settings.sas_file)

  def process: IMap[JawaType, TaintStore] = {
    val sm: SummaryManager = provider.sm
    val components = apk.model.getComponents
    val results: MMap[JawaType, TaintStore] = mmapEmpty
    var i = 0
    components.foreach { comp =>
      i += 1
      reporter.println(s"Processing component $i/${components.size}: ${comp.jawaName}")
      val clazz = apk.getClassOrResolve(comp)
      val eps = clazz.getDeclaredMethods.map(m => m.getSignature)
      val cg = SignatureBasedCallGraph(apk, eps, None)
      val analysis = new BottomUpSummaryGenerator[ApkGlobal](apk, sm, handler,
        TaintSummary(_, _),
        ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed Left: :remain"))
      val store = new TaintStore
      val orderedWUs: IList[WorkUnit[ApkGlobal]] = cg.topologicalSort(true).map { sig =>
        val method = apk.getMethodOrResolve(sig).getOrElse(throw new RuntimeException("Method does not exist: " + sig))
        if(method.isNative) {
          new NativeTaintWU(apk, method, sm, ssm, native_handler)
        } else {
          new TaintWu(apk, method, sm, handler, ssm, store)
        }
      }
      analysis.debug = true
      analysis.build(orderedWUs)
      results(comp) = store
    }
    results.toMap
  }
}