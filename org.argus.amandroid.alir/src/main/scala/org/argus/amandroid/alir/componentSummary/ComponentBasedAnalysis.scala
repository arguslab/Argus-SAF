/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.componentSummary

import org.sireum.util._
import java.util.concurrent.TimeoutException

import org.argus.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper.IntentContent
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.{AndroidRFAConfig, AndroidReachingFactsAnalysis, AndroidReachingFactsAnalysisConfig, IntentHelper}
import org.argus.amandroid.alir.taintAnalysis.{AndroidDataDependentTaintAnalysis, AndroidSourceAndSinkManager}
import org.argus.amandroid.core.Apk
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.controlFlowGraph.{ICFGCallNode, ICFGEntryNode}
import org.argus.jawa.alir.dataDependenceAnalysis._
import org.argus.jawa.alir.dataFlowAnalysis.InterproceduralDataFlowGraph
import org.argus.jawa.alir.pta.Instance
import org.argus.jawa.alir.pta.reachingFactsAnalysis.RFAFactFactory
import org.argus.jawa.alir.taintAnalysis.TaintAnalysisResult
import org.argus.jawa.core.util.MyTimeout
import org.argus.jawa.core.{ClassLoadManager, Global, JawaType}

import scala.concurrent.duration._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object ComponentBasedAnalysis {
  private final val TITLE = "ComponentBasedAnalysis"
  private final val DEBUG = false
  def prepare(global: Global, apk: Apk, parallel: Boolean)(implicit timeout: FiniteDuration): IMap[JawaType, InterproceduralDataFlowGraph] = {
    println(TITLE + ":" + "-------Prepare IDFGs-------")
    AndroidReachingFactsAnalysisConfig.resolve_icc = false // We don't want to resolve ICC at this phase
    var components = apk.getComponents
    val worklist: MList[JawaType] = mlistEmpty ++ components
    val idfgs: MMap[JawaType, InterproceduralDataFlowGraph] = mmapEmpty
    while(worklist.nonEmpty) {
      val component = worklist.remove(0)
      println("-------Analyze component " + component + "--------------")
      try {
        apk.getEnvMap.get(component) match {
          case Some((esig, _)) =>
            val ep = global.getMethod(esig).get // need to double check
            implicit val factory = new RFAFactFactory
            val initialfacts = AndroidRFAConfig.getInitialFactsForMainEnvironment(ep)
            val idfg = AndroidReachingFactsAnalysis(global, apk, ep, initialfacts, new ClassLoadManager, timeout = Some(new MyTimeout(timeout)))
            idfgs(esig.getClassType) = idfg
          case None =>
            global.reporter.error(TITLE, "Component " + component + " did not have environment! Some package or name mismatch maybe in the Manifestfile.")
        }
      } catch {
        case te: TimeoutException => // Timeout happened
          global.reporter.error(TITLE, component + " " + te.getMessage)
        case ex: Exception =>
          if(DEBUG) ex.printStackTrace()
          global.reporter.error(TITLE, "Analyzing component " + component + " has error: " + ex.getMessage)
      } finally {
        System.gc()
      }
      worklist ++= (apk.getComponents -- components)
      components = apk.getComponents
    }
    idfgs.toMap
  }
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class ComponentBasedAnalysis(global: Global, yard: ApkYard) {
  import ComponentBasedAnalysis._
  import ComponentSummaryTable._
  
  val problematicComp: MSet[JawaType] = msetEmpty
  
  /**
   * ComponentBasedAnalysis phase1 is doing intra component analysis for one giving apk.
   */
  def phase1(apk: Apk, parallel: Boolean, idfgs: IMap[JawaType, InterproceduralDataFlowGraph]) = {
    println(TITLE + ":" + "-------Phase 1-------")
    
    var components = apk.getComponents
    idfgs foreach {
      case (comp, idfg) =>
        yard.addIDFG(comp, idfg)
        // do dda on this component
        val iddResult = InterproceduralDataDependenceAnalysis(global, idfg)
        yard.addIDDG(comp, iddResult)
    }
    problematicComp ++= (components -- idfgs.keySet)
    components = apk.getComponents
    apk.getComponents.foreach{
      comp => yard.addComponent(comp, apk)
    }
    components = components -- problematicComp
//    val summaryTables: MMap[JawaClass, ComponentSummaryTable] = mmapEmpty
    
    {if(parallel) components.par else components}.foreach {
      component =>
        println("-------Collect Info for Component " + component + "--------------")
        try {
          // build summary table
          val summaryTable = buildComponentSummaryTable(component)
          yard.addSummaryTable(component, summaryTable)
        } catch {
          case ex: Exception =>
            problematicComp += component
            if(DEBUG) ex.printStackTrace()
            global.reporter.error(TITLE, "Collect Info for Component " + component + " has error: " + ex.getMessage)
        }
    }
  }
  
  def phase2(apks: ISet[Apk], parallel: Boolean): (ISet[Apk], InterproceduralDataDependenceInfo) = {
    val components = apks.map(_.getComponents).fold(Set[JawaType]())(iunion _) -- problematicComp
    println(TITLE + ":" + "-------Phase 2-------" + apks.size + s" apk${if(apks.size > 1)"s" else ""} " + components.size + s" component${if(components.size > 1)"s" else ""}-------")
    val mddg = new MultiDataDependenceGraph[IDDGNode]
    val summaryTables = components.flatMap(yard.getSummaryTable)
    val summaryMap = summaryTables.map(st => (st.component, st)).toMap
    val intentChannels = summaryTables.map(_.get[Intent_Summary](CHANNELS.INTENT_CHANNEL))
    val allIntentCallees = intentChannels.map(_.asCallee).reduceOption{_ ++ _}.getOrElse(imapEmpty)
//    val rpcChannels = summaryTables.map(_.get[RPC_Summary](CHANNELS.RPC_CHANNEL))
//    val allRpcCallees = rpcChannels.map(_.asCallee).reduceOption{_ ++ _}.getOrElse(imapEmpty)
    
    components.foreach{
      component =>
        yard.getIDDG(component) match {
          case Some(iddg) => mddg.addGraph(iddg.getIddg)
          case None =>
        }
    }
    
    {if(parallel) components.par else components}.foreach {
      component =>
        println("-------Link data dependence for component " + component + "--------------")
        try {
          val summaryTable = summaryMap.getOrElse(component, throw new RuntimeException("Summary table does not exist for " + component))
          
          // link the icc edges
          val intent_summary: Intent_Summary = summaryTable.get(CHANNELS.INTENT_CHANNEL)
          intent_summary.asCaller foreach {
            case (callernode, intent_caller) =>
              val icc_callees = allIntentCallees.filter(_._2.matchWith(intent_caller))
              icc_callees foreach {
                case (calleenode, icc_callee) =>
                  println(component + " --icc--> " + calleenode.getOwner.getClassName)
                  val caller_position: Int = 1
                  val callee_position: Int = 0
                  val callerDDGNode = mddg.getIDDGCallArgNode(callernode.asInstanceOf[ICFGCallNode], caller_position)
                  val calleeDDGNode = mddg.getIDDGEntryParamNode(calleenode.asInstanceOf[ICFGEntryNode], callee_position)
                  mddg.addEdge(calleeDDGNode, callerDDGNode)
              }
          }
        } catch {
          case ex: Exception =>
            if(DEBUG) ex.printStackTrace()
            global.reporter.error(TITLE, ex.getMessage)
        }
    }
//    mddg.toDot(new PrintWriter(System.out))
    (apks, new DefaultInterproceduralDataDependenceInfo(mddg))
  }
  
  def phase3(iddResult: (ISet[Apk], InterproceduralDataDependenceInfo), ssm: AndroidSourceAndSinkManager): Option[TaintAnalysisResult[AndroidDataDependentTaintAnalysis.Node, InterproceduralDataDependenceAnalysis.Edge]] = {
    val apks = iddResult._1
    val components = apks.map(_.getComponents).fold(Set[JawaType]())(iunion _) -- problematicComp
    println(TITLE + ":" + "-------Phase 3-------" + apks.size + s" apk${if(apks.size > 1)"s" else ""} " + components.size + s" component${if(components.size > 1)"s" else ""}-------")
    val idfgs = components.flatMap(yard.getIDFG)
    if(idfgs.nonEmpty) {
      try {
        val ptaresult = idfgs.map(_.ptaresult).reduce(_.merge(_))
        val tar = AndroidDataDependentTaintAnalysis(global, iddResult._2, ptaresult, ssm)
        yard.setInterAppTaintAnalysisResult(tar)
        Some(tar)
      } catch {
        case ex: Exception =>
          if(DEBUG) ex.printStackTrace()
          global.reporter.error(TITLE, ex.getMessage)
          None
      }
    } else None
  }
  
  private def buildComponentSummaryTable(component: JawaType): ComponentSummaryTable = {
    val apkOpt: Option[Apk] = yard.getOwnerApk(component)
    if(apkOpt.isEmpty) return new ComponentSummaryTable(component)
    val apk = apkOpt.get
    val idfgOpt = yard.getIDFG(component)
    if(idfgOpt.isEmpty) return new ComponentSummaryTable(component)
    val idfg = idfgOpt.get
    val csp = new ComponentSummaryProvider {
      def getIntentCaller(idfg: InterproceduralDataFlowGraph, intentValue: ISet[Instance], context: Context): ISet[IntentContent] =
        IntentHelper.getIntentContents(idfg.ptaresult, intentValue, context)
    }
    ComponentSummaryTable.buildComponentSummaryTable(apk, component, idfg, csp)
  }
}
