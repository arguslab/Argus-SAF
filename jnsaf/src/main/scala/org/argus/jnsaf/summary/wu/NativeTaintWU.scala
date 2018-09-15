package org.argus.jnsaf.summary.wu

import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.alir.taintAnalysis.SourceAndSinkManager
import org.argus.jawa.core.util._
import org.argus.jawa.core.{JawaMethod, Signature}
import org.argus.jawa.summary.wu.WorkUnit
import org.argus.jawa.summary.{Summary, SummaryManager, SummaryRule}
import org.argus.jnsaf.analysis.NativeMethodHandler

class NativeTaintWU(
    val global: ApkGlobal,
    val method: JawaMethod,
    val sm: SummaryManager,
    ssm: SourceAndSinkManager[ApkGlobal],
    handler: NativeMethodHandler) extends WorkUnit[ApkGlobal] {
  override def needHeapSummary: Boolean = false

  override def generateSummary(suGen: (Signature, IList[SummaryRule]) => Summary): Summary = {
    val sig = method.getSignature
    val res = handler.genSummary(global, sig)
    ssm.parseCode(res._1)
    sm.register(sig.methodName, res._2, fileAndSubsigMatch = false)
    suGen(sig, ilistEmpty)
  }
}
