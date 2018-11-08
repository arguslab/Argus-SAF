/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf.summary.wu

import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.core.JawaMethod
import org.argus.jawa.core.elements.{JawaType, Signature}
import org.argus.jawa.core.util._
import org.argus.jawa.flow.summary.wu.{TaintSummaryRule, WorkUnit}
import org.argus.jawa.flow.summary.{Summary, SummaryManager}
import org.argus.jawa.flow.taintAnalysis.SourceAndSinkManager
import org.argus.jnsaf.analysis.NativeMethodHandler

class NativeTaintWU(
    val global: ApkGlobal,
    val component: JawaType,
    val method: JawaMethod,
    val sm: SummaryManager,
    ssm: SourceAndSinkManager[ApkGlobal],
    handler: NativeMethodHandler,
    depth: Int) extends WorkUnit[ApkGlobal, TaintSummaryRule] {
  override def needHeapSummary: Boolean = false

  override def generateSummary(suGen: (Signature, IList[TaintSummaryRule]) => Summary[TaintSummaryRule]): Summary[TaintSummaryRule] = {
    val sig = method.getSignature
    val res = handler.genSummary(global, component, sig, depth)
    ssm.parseCode(res._1)
    sm.register(sig.methodName, res._2, fileAndSubsigMatch = false)
    suGen(sig, ilistEmpty)
  }

  override def toString: String = s"NativeTaintWU($method)"
}
