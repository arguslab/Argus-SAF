/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf.taint

import hu.ssh.progressbar.ConsoleProgressBar
import org.argus.amandroid.alir.componentSummary.ComponentSummaryTable.CHANNELS
import org.argus.amandroid.alir.componentSummary._
import org.argus.amandroid.alir.pta.model.AndroidModelCallHandler
import org.argus.amandroid.alir.taintAnalysis.AndroidSourceAndSinkManager
import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.core.JawaMethod
import org.argus.jawa.core.elements.{JawaType, Signature}
import org.argus.jawa.core.io.Reporter
import org.argus.jawa.core.util._
import org.argus.jawa.flow.Context
import org.argus.jawa.flow.cfg.{ICFGEntryNode, ICFGNode, InterProceduralControlFlowGraph}
import org.argus.jawa.flow.cg.CHA
import org.argus.jawa.flow.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.flow.pta.PTAResult
import org.argus.jawa.flow.summary.store.TaintStore
import org.argus.jawa.flow.summary.wu._
import org.argus.jawa.flow.summary.{BottomUpSummaryGenerator, SummaryManager, SummaryProvider}
import org.argus.jawa.flow.taintAnalysis.TaintAnalysisResult
import org.argus.jnsaf.analysis.NativeMethodHandler
import org.argus.jnsaf.summary.wu.NativeTaintWU

/**
  * Created by fgwei on 1/26/18.
  */
class JNTaintAnalysis(yard: ApkYard, apk: ApkGlobal,
                      native_handler: NativeMethodHandler,
                      ssm: AndroidSourceAndSinkManager,
                      provider: SummaryProvider,
                      cba: ComponentBasedAnalysis,
                      reporter: Reporter, depth: Int) {
  val handler: AndroidModelCallHandler = new AndroidModelCallHandler

  def process: TaintAnalysisResult = {
    val components = apk.model.getComponentInfos
    var i = 0
    components.foreach { comp =>
      i += 1
      reporter.println(s"Processing component $i/${components.size}: ${comp.compType.jawaName}")
      if(apk.model.isNativeActivity(comp.compType)) {
        val summaryTable: ComponentSummaryTable = new ComponentSummaryTable(comp)
        // Add component as icc callee
        val filters = apk.model.getIntentFilterDB.getIntentFilters(comp.compType)
        val icc_summary: ICC_Summary = summaryTable.get(CHANNELS.ICC)
        val context = new Context(apk.model.getAppName)
        val signature = new Signature("Landroid/app/NativeActivity;.onCreate:(Landroid/os/Bundle;)V")
        context.setContext(signature, signature.signature)
        val node = ICFGEntryNode(context)
        icc_summary.addCallee(node, IntentCallee(apk, comp, filters, apk.model.isExported(comp.compType)))
        val instructions = native_handler.analyseNativeActivity(apk, comp)
        apk.addSummaryTable(comp.compType, summaryTable)
        println("instructions: " + instructions)
      } else {
        val eps: ISet[Signature] = apk.getEntryPoints(comp) ++ apk.model.getCallbackMethods(comp.compType) ++ apk.model.getRpcMethods(comp.compType).keys
        val idfg = process(comp.compType, eps)
        apk.addIDFG(comp.compType, idfg)
        val st = cba.buildComponentSummaryTable(apk, comp)
        apk.addSummaryTable(comp.compType, st)
      }
    }
//    cba.phase1(Set(apk))
//    val intra_result = cba.intraComponentTaintAnalysis(Set(apk), ssm)
    val inter_result = cba.interComponentTaintAnalysis(apk)
    inter_result
  }

  def process(component: JawaType, eps: ISet[Signature]): InterProceduralDataFlowGraph = {
    val sm: SummaryManager = provider.getSummaryManager
    val cg = CHA(apk, eps, None)
    val analysis = new BottomUpSummaryGenerator[ApkGlobal, TaintSummaryRule](apk, sm, handler,
      TaintSummary(_, _),
      ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed Left: :remain"))
    val store = new TaintStore
    val orderedWUs: IList[WorkUnit[ApkGlobal, TaintSummaryRule]] = cg.topologicalSort(true).map { sig =>
      val method = apk.getMethodOrResolve(sig).getOrElse(throw new RuntimeException("Method does not exist: " + sig))
      if(method.isNative) {
        new NativeTaintWU(apk, component, method, sm, ssm, native_handler, depth)
      } else {
        new TaintWu(apk, method, sm, handler, ssm, store)
      }
    }
    analysis.debug = true
    analysis.build(orderedWUs)
    apk.addComponentTaintAnalysisResult(component, store)
    val icfg = new InterProceduralControlFlowGraph[ICFGNode]
    val ptaresult = new PTAResult
    val methods: MList[JawaMethod] = mlistEmpty
    orderedWUs.foreach {
      case wu: DataFlowWu[ApkGlobal, TaintSummaryRule] =>
        methods += wu.method
        ptaresult.merge(wu.ptaresult)
      case _ =>
    }
    icfg.buildWithExisting(apk.nameUri, methods.toList, ptaresult)
    InterProceduralDataFlowGraph(icfg, ptaresult)
  }
}