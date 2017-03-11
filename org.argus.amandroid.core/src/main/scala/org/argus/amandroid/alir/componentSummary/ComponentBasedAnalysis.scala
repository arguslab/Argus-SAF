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
import org.argus.amandroid.core.{AndroidConstants, Apk}
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.controlFlowGraph._
import org.argus.jawa.alir.dataDependenceAnalysis._
import org.argus.jawa.alir.dataFlowAnalysis.InterproceduralDataFlowGraph
import org.argus.jawa.alir.pta.Instance
import org.argus.jawa.alir.pta.reachingFactsAnalysis.RFAFactFactory
import org.argus.jawa.alir.taintAnalysis.TaintAnalysisResult
import org.argus.jawa.core.util.MyTimeout
import org.argus.jawa.core.{ClassLoadManager, Global, JawaType}

import scala.compat.Platform.EOL
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
          global.reporter.error(TITLE, "Analyzing component " + component + " has error: " + ex.getMessage + "\n" + ex.getStackTrace.mkString("", EOL, EOL))
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
  def phase1(apk: Apk, parallel: Boolean, idfgs: IMap[JawaType, InterproceduralDataFlowGraph]): Unit = {
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
    val components = apks.map(_.getComponents).fold(Set[JawaType]())(iunion) -- problematicComp
    println(TITLE + ":" + "-------Phase 2-------" + apks.size + s" apk${if(apks.size > 1)"s" else ""} " + components.size + s" component${if(components.size > 1)"s" else ""}-------")
    val mddg = new MultiDataDependenceGraph[IDDGNode]
    val summaryTables = components.flatMap(yard.getSummaryTable)
    val summaryMap = summaryTables.map(st => (st.component, st)).toMap
    val iccChannels = summaryTables.map(_.get[ICC_Summary](CHANNELS.ICC))
    val allICCCallees = iccChannels.map(_.asCallee).reduceOption{_ ++ _}.getOrElse(isetEmpty)
    val rpcChannels = summaryTables.map(_.get[RPC_Summary](CHANNELS.RPC))
    val allRpcCallees = rpcChannels.map(_.asCallee).reduceOption{_ ++ _}.getOrElse(imapEmpty)
    val sfChannels = summaryTables.map(_.get[StaticField_Summary](CHANNELS.STATIC_FIELD))
    val allSFCallees = sfChannels.map(_.asCallee).reduceOption{_ ++ _}.getOrElse(isetEmpty)
    
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
          val bindServices: MSet[JawaType] = msetEmpty
          val forResultTargets: MSet[JawaType] = msetEmpty
          // link the intent edges
          val icc_summary: ICC_Summary = summaryTable.get(CHANNELS.ICC)
          icc_summary.asCaller foreach {
            case (callernode, icc_caller) =>
              val icc_callees = allICCCallees.filter(_._2.matchWith(icc_caller))
              icc_callees foreach { case (calleeNode, icc_callee) =>
                icc_callee match {
                  case _: IntentCallee =>
                    println(component + " --icc--> " + calleeNode.getOwner.getClassName)
                    val caller_position: Int = 1
                    val callee_position: Int = 0
                    val callerDDGNode = mddg.getIDDGCallArgNode(callernode.asInstanceOf[ICFGCallNode], caller_position)
                    val calleeDDGNode = mddg.getIDDGEntryParamNode(calleeNode.asInstanceOf[ICFGEntryNode], callee_position)
                    mddg.addEdge(calleeDDGNode, callerDDGNode)
                    if(callernode.asInstanceOf[ICFGCallNode].getCalleeSig.getSubSignature == AndroidConstants.BIND_SERVICE) {
                      bindServices += calleeNode.getOwner.getClassType
                    } else if(AndroidConstants.isStartActivityForResultMethod(callernode.asInstanceOf[ICFGCallNode].getCalleeSig.getSubSignature)) {
                      forResultTargets += calleeNode.getOwner.getClassType
                    }
                  case _ =>
                }
              }
              allICCCallees.foreach{
                case (_, callee) =>
                  callee match {
                    case irc: IntentResultCallee => irc.addTargets(forResultTargets.toSet)
                    case _ =>
                  }
              }
              allICCCallees.filter(_._2.matchWith(icc_caller)) foreach { case (calleeNode, icc_callee) =>
                icc_callee match {
                  case irc: IntentResultCallee =>
                    println(component + " --icc: setResult--> " + calleeNode.getOwner.getClassName)
                    val caller_position: Int = 2
                    val callee_position: Int = 3
                    val callerDDGNode = mddg.getIDDGCallArgNode(callernode.asInstanceOf[ICFGCallNode], caller_position)
                    val calleeDDGNode = mddg.getIDDGEntryParamNode(calleeNode.asInstanceOf[ICFGEntryNode], callee_position)
                    mddg.addEdge(calleeDDGNode, callerDDGNode)
                  case _ =>
                }
              }
          }

          // link the rpc edges
          val rpc_summary: RPC_Summary = summaryTable.get(CHANNELS.RPC)
          rpc_summary.asCaller foreach {
            case (callernode, rpc_caller) =>
              rpc_caller.asInstanceOf[RPCCaller].addBindServices(bindServices.toSet)
              val rpc_callees = allRpcCallees.filter(_._2.matchWith(rpc_caller))
              rpc_callees foreach {
                case (calleenode, rpc_callee) =>
                  rpc_callee match {
                    case hc: MessengerCallee =>
                      println(component + " --rpc: Messenger.send to Handler.handleMessage--> " + calleenode.getOwner.getClassName)
                      val callerDDGNode = mddg.getIDDGCallArgNode(callernode.asInstanceOf[ICFGCallNode], 1)
                      val calleeDDGNode = mddg.getIDDGEntryParamNode(calleenode.asInstanceOf[ICFGEntryNode], 1)
                      mddg.addEdge(calleeDDGNode, callerDDGNode)
                    case bsc: BoundServiceCallee =>
                      println(component + " --rpc: " + bsc.sig + "--> " + calleenode.getOwner.getClassName)
                      for (i <- callernode.asInstanceOf[ICFGCallNode].argNames.indices) {
                        val callerDDGNode = mddg.getIDDGCallArgNode(callernode.asInstanceOf[ICFGCallNode], i)
                        val calleeDDGNode = mddg.getIDDGEntryParamNode(calleenode.asInstanceOf[ICFGEntryNode], i)
                        mddg.addEdge(calleeDDGNode, callerDDGNode)
                      }
                    case bsrc: BoundServiceReturnCallee =>
                      println(component + " --rpc return: " + bsrc.callee_sig + "--> " + calleenode.getOwner.getClassName)
                      for (i <- calleenode.asInstanceOf[ICFGReturnNode].argNames.indices) {
                        val callerDDGNode = mddg.getIDDGExitParamNode(callernode.asInstanceOf[ICFGExitNode], i)
                        val calleeDDGNode = mddg.getIDDGReturnArgNode(calleenode.asInstanceOf[ICFGReturnNode], i)
                        mddg.addEdge(calleeDDGNode, callerDDGNode)
                      }
                      yard.getIDFG(component) match {
                        case Some(idfg) =>
                          val calleeDDGNode = mddg.getIDDGReturnVarNode(calleenode.asInstanceOf[ICFGReturnNode])
                          idfg.icfg.predecessors(callernode) foreach {
                            case nn: ICFGNormalNode =>
                              val callerDDGNode = mddg.getIDDGNormalNode(nn)
                              mddg.addEdge(calleeDDGNode, callerDDGNode)
                            case _ =>
                          }
                        case None =>
                      }
                    case _ =>
                  }
              }
          }

          // link the static field edges
          val sf_summary: StaticField_Summary = summaryTable.get(CHANNELS.STATIC_FIELD)
          sf_summary.asCaller foreach {
            case (callernode, sf_write) =>
              val sf_reads = allSFCallees.filter(_._2.matchWith(sf_write))
              sf_reads foreach {
                case (calleenode, _) =>
                  println(component + " --static field: " + sf_write.asInstanceOf[StaticFieldWrite].fqn + "--> " + calleenode.getOwner.getClassName)
                  val callerDDGNode = mddg.getIDDGNormalNode(callernode.asInstanceOf[ICFGNormalNode])
                  val calleeDDGNode = mddg.getIDDGNormalNode(calleenode.asInstanceOf[ICFGNormalNode])
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
    val components = apks.map(_.getComponents).fold(Set[JawaType]())(iunion) -- problematicComp
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
    ComponentSummaryTable.buildComponentSummaryTable(global, apk, component, idfg, csp)
  }
}
