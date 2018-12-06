/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.summary.gpu

import java.io.FileWriter

import hu.ssh.progressbar.console.ConsoleProgressBar
import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.pta.model.AndroidModelCallHandler
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.core.ApkGlobal
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.jawa.alir.JawaAlirInfoProvider
import org.argus.jawa.alir.cfg.{CFGLocationNode, CFGNode, CFGVirtualNode}
import org.argus.jawa.alir.reachability.SignatureBasedCallGraph
import org.argus.jawa.ast.MethodDeclaration
import org.argus.jawa.core._
import org.argus.jawa.core.util._
import org.argus.jawa.summary.susaf.rule.HeapSummary
import org.argus.jawa.summary.wu.{HeapSummaryWu, WorkUnit}
import org.argus.jawa.summary.{BottomUpSummaryGenerator, SummaryManager}
import org.jgrapht.ext.ComponentNameProvider

object GPUSummaryBasedAnalysis {

  private def vLabelProvider(body: MethodDeclaration): ComponentNameProvider[CFGNode] = {
    case ln: CFGLocationNode =>
      val locUri = ln.toString
      val l = body.resolvedBody.location(locUri)
      l.statement.toStructure
    case _: CFGVirtualNode =>
      body.signature.signature + " " + body.params.map(param => s"${param.typ.typ}:${param.name}").mkString(",")
  }

  def generate(apk: ApkGlobal, ep: Signature, outputUri: FileResourceUri): Unit = {
    val cg = SignatureBasedCallGraph(apk, Set(ep), None)
    val sm: SummaryManager = new AndroidSummaryProvider(apk).getSummaryManager
    val handler: AndroidModelCallHandler = new AndroidModelCallHandler
    val analysis = new BottomUpSummaryGenerator[Global](apk, sm, handler,
      HeapSummary(_, _),
      ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed Left: :remain"))
    val orderedWUs: IList[WorkUnit[Global]] = cg.topologicalSort(true).map { sig =>
      val method = apk.getMethodOrResolve(sig).getOrElse(throw new RuntimeException("Method does not exist: " + sig))
      new HeapSummaryWu(apk, method, sm, handler)
    }
    val resultUri = FileUtil.appendFileName(outputUri, apk.model.getAppName + ".result")
    val writer = new FileWriter(FileUtil.toFile(resultUri), true)
    writer.write("Entry point: " + ep.signature + "\n")
    TimeUtil.timed("Analysis time", writer)(analysis.build(orderedWUs))
    try {
      orderedWUs.foreach {
        case wu: HeapSummaryWu =>
          if (wu.method.getDeclaringClass.isApplicationClass && wu.method.isConcrete) {
            writer.write(wu.method.getSignature.signature + "\nCFG:\n")
            val body = wu.method.getBody
            val cfg = JawaAlirInfoProvider.getCfg(wu.method)
            cfg.toGraphML(writer, vlp = vLabelProvider(body))
            writer.write("\nPTA result:\n")
            writer.write(wu.ptaresult.pprint())
            writer.write("\n\n")
          }
        case _ =>
      }
    } catch {
      case e: Exception =>
        e.printStackTrace()
    } finally {
      writer.flush()
      writer.close()
    }
  }

  def apply(apkPath: String, outputPath: String, falseDelate: Boolean): Unit = {
    val apkUri = FileUtil.toUri(apkPath)
    val outputUri = FileUtil.toUri(outputPath)
    val reporter = new PrintReporter(MsgLevel.INFO)
    val yard = new ApkYard(reporter)
    val layout = DecompileLayout(outputUri)
    val strategy = DecompileStrategy(layout)
    val settings = DecompilerSettings(debugMode = false, forceDelete = falseDelate, strategy, reporter)
    val apk = yard.loadApk(apkUri, settings, collectInfo = true, resolveCallBack = true)
    val entryPoints: ISet[Signature] = apk.model.getComponentInfos.flatMap(apk.getEntryPoints)

    def handleEntryPoint: Signature => Unit = { ep =>
      generate(apk, ep, outputUri)
    }

    val progressBar = ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed Left: :remain")
    ProgressBarUtil.withProgressBar("Building GPU results...", progressBar)(entryPoints, handleEntryPoint)
    reporter.println(s"GPUSummaryBasedAnalysis done with method size ${entryPoints.size}.")
  }
}