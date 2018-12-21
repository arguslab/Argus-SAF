/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.componentSummary

import java.util.concurrent.TimeoutException

import org.argus.amandroid.alir.componentSummary.ComponentSummaryTable.CHANNELS
import org.argus.amandroid.alir.pta.model.AndroidModelCallHandler
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.{AndroidReachingFactsAnalysis, AndroidReachingFactsAnalysisConfig}
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.alir.taintAnalysis.{AndroidDataDependentTaintAnalysis, AndroidSourceAndSinkManager}
import org.argus.amandroid.core.ApkGlobal
import org.argus.amandroid.core.parser.ComponentInfo
import org.argus.jawa.core.ClassLoadManager
import org.argus.jawa.core.elements.{JawaType, Signature}
import org.argus.jawa.core.util.{MyTimeout, WorklistAlgorithm, _}
import org.argus.jawa.flow.Context
import org.argus.jawa.flow.cfg._
import org.argus.jawa.flow.dda._
import org.argus.jawa.flow.pta.PTAResult
import org.argus.jawa.flow.summary.store.{TSTaintPath, TaintStore}
import org.argus.jawa.flow.taintAnalysis._

import scala.compat.Platform.EOL
import scala.concurrent.duration._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object ComponentBasedAnalysis {
  private final val TITLE = "ComponentBasedAnalysis"
  private final val DEBUG = true
  def prepare(apks: ISet[ApkGlobal])(implicit timeout: FiniteDuration): Unit = {
    apks.foreach { apk =>
      println("Prepare IDFGs for: " + apk.model.getAppName)
      var components = apk.model.getComponents
      val worklist = new WorklistAlgorithm[JawaType] {
        override def processElement(component: JawaType): Unit = {
          println("--Analyzing component: " + component)
          try {
            apk.model.getEnvMap.get(component) match {
              case Some((esig, _)) =>
                val ep = apk.getMethod(esig).get
                val initialfacts = AndroidReachingFactsAnalysisConfig.getInitialFactsForMainEnvironment(ep)
                val icfg = new InterProceduralControlFlowGraph[ICFGNode]
                val ptaresult = new PTAResult
                val sp = new AndroidSummaryProvider(apk)
                val analysis = new AndroidReachingFactsAnalysis(
                  apk, icfg, ptaresult, new AndroidModelCallHandler, sp.getSummaryManager, new ClassLoadManager,
                  AndroidReachingFactsAnalysisConfig.resolve_static_init,
                  timeout = Some(new MyTimeout(timeout)))
                val idfg = analysis.build(ep, initialfacts, new Context(apk.nameUri))
                apk.addIDFG(component, idfg)
              case None =>
                apk.reporter.error(TITLE, "Component " + component + " did not have environment! Some package or name mismatch maybe in the Manifest.")
            }
          } catch {
            case te: TimeoutException => // Timeout happened
              apk.reporter.error(TITLE, component + " " + te.getMessage)
            case ex: Exception =>
              if (DEBUG) ex.printStackTrace()
              apk.reporter.error(TITLE, "Analyzing component " + component + " has error: " + ex.getMessage + "\n" + ex.getStackTrace.mkString("", EOL, EOL))
          } finally {
            System.gc()
          }
          worklist = (apk.model.getComponents -- components) ++: worklist
          components = apk.model.getComponents
        }
      }
      worklist.run(worklist.worklist = components.toList)
    }
  }
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class ComponentBasedAnalysis(yard: ApkYard) {
  import ComponentBasedAnalysis._
  
  val problematicComp: MMap[FileResourceUri, MSet[ComponentInfo]] = mmapEmpty
  val customICCMap: MMap[Signature, MSet[String]] = mmapEmpty
  
  /**
   * ComponentBasedAnalysis phase1 is doing intra component analysis for one giving apk.
   */
  def phase1(apks: ISet[ApkGlobal]): Unit = {
    println(TITLE + ":" + " Phase 1:")
    apks.foreach { apk =>
      println("--Analyzing " + apk.model.getAppName)
      val idfgs = apk.getIDFGs
      idfgs foreach { case (comp, idfg) =>
        println("----Data Dependence Analysis: " + comp)
        // do dda on this component
        val iddResult = InterProceduralDataDependenceAnalysis(apk, idfg)
        apk.addIDDG(comp, iddResult)
      }
      var components = apk.model.getComponentInfos
      problematicComp.getOrElseUpdate(apk.nameUri, msetEmpty) ++= components.filterNot(comp => idfgs.contains(comp.compType))
      components = components -- problematicComp(apk.nameUri)

      components.foreach { component =>
        println("----Building ST for component: " + component)
        try {
          // build summary table
          val summaryTable = buildComponentSummaryTable(apk, component)
          apk.addSummaryTable(component.compType, summaryTable)
        } catch {
          case ex: Exception =>
            problematicComp(apk.nameUri) += component
            if (DEBUG) ex.printStackTrace()
            yard.reporter.error(TITLE, "Collect Info for Component " + component + " has error: " + ex.getMessage)
        }
      }
    }
  }
  
  def phase2(apks: ISet[ApkGlobal]): (ISet[ApkGlobal], InterProceduralDataDependenceInfo) = {
    val components: ISet[(ApkGlobal, ComponentInfo)] = apks.flatMap { apk =>
      apk.model.getComponentInfos.map(comp => apk -> comp)
    }
    println(TITLE + ":" + " Phase 2-------" + apks.size + s" apk${if (apks.size > 1) "s" else ""} " + components.size + s" component${if (components.size > 1) "s" else ""}-------")
    val mddg = ComponentSummaryTable.buildMultiDataDependentGraph(components, yard.reporter)
//    mddg.toDot(new java.io.PrintWriter(System.out))
    (apks, new DefaultInterProceduralDataDependenceInfo(mddg))
  }
  
  def phase3(iddResult: (ISet[ApkGlobal], InterProceduralDataDependenceInfo), ssm: AndroidSourceAndSinkManager): Option[TaintAnalysisResult] = {
    val apks = iddResult._1
    val components: ISet[(ApkGlobal, ComponentInfo)] = apks.flatMap { apk =>
      (apk.model.getComponentInfos -- problematicComp.getOrElse(apk.nameUri, msetEmpty)).map(comp => apk -> comp)
    }
    println(TITLE + ":" + " Phase 3-------" + apks.size + s" apk${if(apks.size > 1)"s" else ""} " + components.size + s" component${if(components.size > 1)"s" else ""}-------")
    val idfgs = components.flatMap{ case (apk, component) => apk.getIDFG(component.compType)}
    if(idfgs.nonEmpty) {
      try {
        val ptaresult = idfgs.map(_.ptaresult).reduce(_.merge(_))
        val tar = AndroidDataDependentTaintAnalysis(yard, iddResult._2, ptaresult, ssm)
        yard.setInterAppTaintAnalysisResult(tar)
        apks.foreach(_.addTaintAnalysisResult(tar))
        Some(tar)
      } catch {
        case ex: Exception =>
          if(DEBUG) ex.printStackTrace()
          yard.reporter.error(TITLE, ex.getMessage)
          None
      }
    } else None
  }

  def intraComponentTaintAnalysis(apks: ISet[ApkGlobal], ssm: AndroidSourceAndSinkManager): IMap[ApkGlobal, IMap[ComponentInfo, TaintAnalysisResult]] = {
    val components: ISet[(ApkGlobal, ComponentInfo)] = apks.flatMap { apk =>
      apk.model.getComponentInfos.map(comp => apk -> comp)
    }
    val result: MMap[ApkGlobal, MMap[ComponentInfo, TaintAnalysisResult]] = mmapEmpty
    components.foreach{ case (apk, component) =>
      if(apk.model.isNativeActivity(component.compType)) {

      } else {
        val idfg = apk.getIDFG(component.compType).get
        val iddg = apk.getIDDG(component.compType).get
        val iddi = new DefaultInterProceduralDataDependenceInfo(iddg.getIddg)
        val tar = AndroidDataDependentTaintAnalysis(yard, iddi, idfg.ptaresult, ssm)
        apk.addComponentTaintAnalysisResult(component.compType, tar)
        result.getOrElseUpdate(apk, mmapEmpty).getOrElseUpdate(component, tar)
      }
    }
    result.map{ case (apk, comps) => apk -> comps.toMap }.toMap
  }

  def interComponentTaintAnalysis(apk: ApkGlobal): TaintAnalysisResult = {
    val summaryTables = apk.getSummaryTables.values.toSet
    val summaryMap = summaryTables.map(st => (st.component.compType, st)).toMap
    val iccChannels = summaryTables.map(_.get[ICC_Summary](CHANNELS.ICC))
    val allICCCallees: ISet[(ICFGNode, CSTCallee)] = iccChannels.flatMap(_.asCallee)

    val taint_result = new TaintStore
    apk.getComponentTaintAnalysisResults.foreach { case (_, tar) =>
      taint_result.addTaintPaths(tar.getTaintedPaths)
    }
    apk.getComponentTaintAnalysisResults.foreach { case (component, tar) =>
      try {
        if(!apk.model.isNativeActivity(component)) {
          val summaryTable = summaryMap.getOrElse(component, throw new RuntimeException("Summary table does not exist for " + component))
          // link the intent edges
          val icc_summary: ICC_Summary = summaryTable.get(CHANNELS.ICC)
          icc_summary.asCaller foreach {
            case (_, icc_caller) =>
              val icc_sink_paths = tar.getTaintedPaths.filter { path =>
                path.getSink.descriptor.typ == SourceAndSinkCategory.ICC_SINK
              }
              if (icc_sink_paths.nonEmpty) {
                taint_result.removeTaintPaths(icc_sink_paths)
                val icc_callees = allICCCallees.filter(_._2.matchWith(icc_caller))
                icc_caller match {
                  case _: IntentCaller =>
                    icc_callees foreach { case (_, icc_callee) =>
                      icc_callee match {
                        case intent_callee: IntentCallee =>
                          apk.reporter.println(component + " --intent--> " + intent_callee.component.compType)
                          apk.getComponentTaintAnalysisResult(intent_callee.component.compType) match {
                            case Some(callee_tar) =>
                              val icc_source_paths = callee_tar.getTaintedPaths.filter { path =>
                                path.getSource.descriptor.typ == SourceAndSinkCategory.ICC_SOURCE
                              }
                              if (icc_source_paths.nonEmpty) {
                                taint_result.removeTaintPaths(icc_source_paths)
                                icc_sink_paths.foreach { sink_path =>
                                  icc_source_paths.foreach { source_path =>
                                    val new_path = TSTaintPath(sink_path.getSource, source_path.getSink)
                                    new_path.path = sink_path.getPath ++ source_path.getPath
                                    taint_result.addTaintPath(new_path)
                                  }
                                }
                              }
                            case None =>
                          }
                        case _ =>
                      }
                    }
                  case _ =>
                }
              }
          }
        }
      } catch {
        case ex: Exception =>
          if (DEBUG) ex.printStackTrace()
          apk.reporter.error(TITLE, ex.getMessage)
      }
    }
    System.err.println(taint_result)
    taint_result
  }
  
  def buildComponentSummaryTable(apk: ApkGlobal, component: ComponentInfo): ComponentSummaryTable = {
    val idfgOpt = apk.getIDFG(component.compType)
    if(idfgOpt.isEmpty) return new ComponentSummaryTable(component)
    val idfg = idfgOpt.get
    ComponentSummaryTable.buildComponentSummaryTable(apk, component, idfg, customICCMap.toMap)
  }
}
