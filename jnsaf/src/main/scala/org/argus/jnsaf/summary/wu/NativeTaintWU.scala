package org.argus.jnsaf.summary.wu

import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.core.JawaMethod
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util._
import org.argus.jawa.flow.summary.wu.{TaintSummaryRule, WorkUnit}
import org.argus.jawa.flow.summary.{Summary, SummaryManager}
import org.argus.jawa.flow.taintAnalysis.SourceAndSinkManager
import org.argus.jnsaf.analysis.NativeMethodHandler

class NativeTaintWU(
    val global: ApkGlobal,
    val method: JawaMethod,
    val sm: SummaryManager,
    ssm: SourceAndSinkManager[ApkGlobal],
    handler: NativeMethodHandler) extends WorkUnit[ApkGlobal, TaintSummaryRule] {
  override def needHeapSummary: Boolean = false

  override def generateSummary(suGen: (Signature, IList[TaintSummaryRule]) => Summary[TaintSummaryRule]): Summary[TaintSummaryRule] = {
    val sig = method.getSignature
    val res = handler.genSummary(global, sig)
    ssm.parseCode(res._1)
    sm.register(sig.methodName, res._2, fileAndSubsigMatch = false)
    suGen(sig, ilistEmpty)
  }
}
