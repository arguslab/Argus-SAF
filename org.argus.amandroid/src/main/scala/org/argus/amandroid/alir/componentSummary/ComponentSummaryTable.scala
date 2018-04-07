/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.componentSummary

import org.argus.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper
import org.argus.amandroid.core.model.Intent
import org.argus.amandroid.core.parser.IntentFilter
import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.cfg._
import org.argus.jawa.alir.dda.{IDDGNode, MultiDataDependenceGraph}
import org.argus.jawa.alir.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.alir.pta.{Instance, VarSlot}
import org.argus.jawa.ast.{AssignmentStatement, StaticFieldAccessExpression}
import org.argus.jawa.core._
import org.argus.jawa.core.util._

trait ComponentSummaryProvider {
  def getIntentCaller(idfg: InterProceduralDataFlowGraph, intentValue: ISet[Instance], context: Context): ISet[Intent]
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object ComponentSummaryTable {
  private final val DEBUG: Boolean = false
  private final val TITLE: String = "ComponentSummaryTable"

  object CHANNELS extends Enumeration {
    val ICC, RPC, STATIC_FIELD = Value
  }
  
  def buildComponentSummaryTable(component: Component, idfg: InterProceduralDataFlowGraph): ComponentSummaryTable = {
    val apk = component.apk
    val summaryTable: ComponentSummaryTable = new ComponentSummaryTable(component)
    // Add component as icc callee
    val filters = apk.model.getIntentFilterDB.getIntentFilters(component.typ)
    val icc_summary: ICC_Summary = summaryTable.get(CHANNELS.ICC)
    icc_summary.addCallee(idfg.icfg.entryNode, IntentCallee(component, apk.model.getComponentType(component.typ).get, filters, apk.model.isExported(component.typ)))
    
    val rpcs = apk.model.getRpcMethods(component.typ)
    val rpc_summary: RPC_Summary = summaryTable.get(CHANNELS.RPC)

    val sf_summary: StaticField_Summary = summaryTable.get(CHANNELS.STATIC_FIELD)

    // Collect info from idfg for component as icc caller or rpc caller or others
    idfg.icfg.nodes.filter(n => apk.model.getEnvMap(component.typ)._1 != n.getOwner) foreach {
      case nn: ICFGNormalNode =>
        val method = apk.getMethod(nn.getOwner).get
        method.getBody.resolvedBody.locations(nn.locIndex).statement match {
          case as: AssignmentStatement =>
            val lhs = as.lhs
            val rhs = as.rhs
            lhs match {
              case ne: StaticFieldAccessExpression =>
                sf_summary.addCaller(nn, StaticFieldWrite(component, new FieldFQN(ne.name, ne.typ)))
              case _ =>
            }
            rhs match {
              case ne: StaticFieldAccessExpression =>
                sf_summary.addCallee(nn, StaticFieldRead(component, new FieldFQN(ne.name, ne.typ)))
              case _ =>
            }
          case _ =>
        }
      case en: ICFGEntryNode =>
        // Add onActivityResult as icc callee
        val activity = apk.getClassOrResolve(new JawaType("android.app.Activity"))
        val current = apk.getClassOrResolve(en.getOwner.getClassType)
        if(activity.isAssignableFrom(current)
          && en.getOwner.getSubSignature == "onActivityResult:(IILandroid/content/Intent;)V") {
          icc_summary.addCallee(en, IntentResultCallee(Component(apk, en.getOwner.getClassType)))
        }
        val handler = apk.getClassOrResolve(new JawaType("android.os.Handler"))
        rpcs.filter(rpc => rpc._1 == en.context.getMethodSig).foreach { case (rpc, allow_remote) =>
          val rpcClazz = apk.getClassOrResolve(rpc.classTyp)
          // Add handleMessage as rpc callee
          if(handler.isAssignableFrom(rpcClazz)
            && rpc.getSubSignature == "handleMessage:(Landroid/os/Message;)V") {
            rpc_summary.addCallee(en, MessengerCallee(component, rpc))
          } else {
            rpc_summary.addCallee(en, BoundServiceCallee(component, rpc, allow_remote))
          }
        }
      case cn: ICFGCallNode =>
        val callees = cn.getCalleeSet
        val activity = apk.getClassOrResolve(new JawaType("android.app.Activity"))
        val messenger = apk.getClassOrResolve(new JawaType("android.os.Messenger"))
        callees foreach { callee =>
          val calleeSig = callee.callee
          val ptsmap = idfg.ptaresult.getPTSMap(cn.context)
          if (AndroidConstants.isIccMethod(calleeSig.getSubSignature)) {
            // add icc call as icc caller
            val callTyp = AndroidConstants.getIccCallType(calleeSig.getSubSignature)
            val intentSlot = VarSlot(cn.argNames(1))
            val intentValue: ISet[Instance] = ptsmap.getOrElse(intentSlot, isetEmpty)
            val intentContents = IntentHelper.getIntentContents(idfg.ptaresult, intentValue, cn.context)
            intentContents foreach { intentContent =>
              icc_summary.addCaller(cn, IntentCaller(component, callTyp, intentContent))
            }
          }
          val calleeClazz = apk.getClassOrResolve(calleeSig.getClassType)
          if(activity.isAssignableFrom(calleeClazz)
            && AndroidConstants.isSetResult(calleeSig.getSubSignature)) {
            // add setResult as icc caller
            icc_summary.addCaller(cn, IntentResultCaller(component))
          }
          if(messenger.isAssignableFrom(calleeClazz)
            && calleeSig.getSubSignature == "send:(Landroid/os/Message;)V") {
            val rpc_summary: RPC_Summary = summaryTable.get(CHANNELS.RPC)
            rpc_summary.addCaller(cn, MessengerCaller(component, calleeSig))
          } else if(calleeSig.getClassType.baseType.unknown) {
            apk.model.getRpcMethods.foreach { case (rpc, _) =>
              if(rpc.getSubSignature == calleeSig.getSubSignature) {
                val calleeTyp = calleeSig.classTyp.removeUnknown()
                val calleeCls = apk.getClassOrResolve(calleeTyp)
                val rpcCls = apk.getClassOrResolve(rpc.classTyp)
                if((calleeCls.isInterface && apk.getClassHierarchy.getAllImplementersOf(calleeCls).contains(rpcCls))
                  || (!calleeCls.isInterface && apk.getClassHierarchy.isClassRecursivelySubClassOfIncluding(rpcCls, calleeCls))) {
                  val rpc_summary: RPC_Summary = summaryTable.get(CHANNELS.RPC)
                  rpc_summary.addCaller(cn, BoundServiceCaller(component, rpc))
                }
              }
            }
          } else {
            if(apk.model.getRpcMethods.contains(calleeSig))
              rpc_summary.addCaller(cn, BoundServiceCaller(component, calleeSig))
          }
        }
      case en: ICFGExitNode =>
        rpcs.filter(rpc => rpc._1 == en.context.getMethodSig).foreach {
          rpc =>
            if(rpc._1.getReturnType != new JawaType("void")) {
              // Add return node as rpc callee
              rpc_summary.addCaller(en, BoundServiceReturnCaller(component, rpc._1, rpc._2))
            }
        }
      case rn: ICFGReturnNode =>
        val callees = rn.getCalleeSet
        callees foreach { callee =>
          val calleeSig = callee.callee
          if(calleeSig.getClassType.baseType.unknown) {
            apk.model.getRpcMethods.foreach { case (rpc, _) =>
              if(rpc.getSubSignature == calleeSig.getSubSignature) {
                val calleeTyp = calleeSig.classTyp.removeUnknown()
                val calleeCls = apk.getClassOrResolve(calleeTyp)
                val rpcCls = apk.getClassOrResolve(rpc.classTyp)
                if((calleeCls.isInterface && apk.getClassHierarchy.getAllImplementersOf(calleeCls).contains(rpcCls))
                  || (!calleeCls.isInterface && apk.getClassHierarchy.isClassRecursivelySubClassOfIncluding(rpcCls, calleeCls))) {
                  val rpc_summary: RPC_Summary = summaryTable.get(CHANNELS.RPC)
                  rpc_summary.addCallee(rn, BoundServiceReturnCallee(component, rpc))
                }
              }
            }
          } else {
            if(apk.model.getRpcMethods.contains(calleeSig))
              rpc_summary.addCallee(rn, BoundServiceReturnCallee(component, calleeSig))
          }
        }
      case _ =>
    }
    summaryTable
  }

  def buildMultiDataDependentGraph(components: ISet[Component], reporter: Reporter): MultiDataDependenceGraph[IDDGNode] = {
    val mddg = new MultiDataDependenceGraph[IDDGNode]
    val summaryTables = components.flatMap(component => component.apk.getSummaryTable(component.typ))
    val summaryMap = summaryTables.map(st => (st.component, st)).toMap
    val iccChannels = summaryTables.map(_.get[ICC_Summary](CHANNELS.ICC))
    val allICCCallees: ISet[(ICFGNode, CSTCallee)] = iccChannels.flatMap(_.asCallee)
    val rpcChannels = summaryTables.map(_.get[RPC_Summary](CHANNELS.RPC))
    val allRpcCallees: ISet[(ICFGNode, CSTCallee)] = rpcChannels.flatMap(_.asCallee)
    val sfChannels = summaryTables.map(_.get[StaticField_Summary](CHANNELS.STATIC_FIELD))
    val allSFCallees: ISet[(ICFGNode, CSTCallee)] = sfChannels.flatMap(_.asCallee)

    components.foreach { component =>
      component.apk.getIDDG(component.typ) match {
        case Some(iddg) => mddg.addGraph(iddg.getIddg)
        case None =>
      }
    }

    reporter.println("--Link inter-component data dependence")
    components.foreach { component =>
      try {
        val summaryTable = summaryMap.getOrElse(component, throw new RuntimeException("Summary table does not exist for " + component))
        val bindServices: MSet[Component] = msetEmpty
        val forResultTargets: MSet[Component] = msetEmpty
        // link the intent edges
        val icc_summary: ICC_Summary = summaryTable.get(CHANNELS.ICC)
        icc_summary.asCaller foreach {
          case (callernode, icc_caller) =>
            val icc_callees = allICCCallees.filter(_._2.matchWith(icc_caller))
            icc_callees foreach { case (calleeNode, icc_callee) =>
              icc_callee match {
                case ic_callee: IntentCallee =>
                  reporter.println(component + " --icc--> " + icc_callee.asInstanceOf[IntentCallee].component)
                  val caller_position: Int = 1
                  val callee_position: Int = 1
                  val callerDDGNode = mddg.getIDDGCallArgNode(callernode.asInstanceOf[ICFGCallNode], caller_position)
                  val calleeDDGNode = mddg.getIDDGEntryParamNode(calleeNode.asInstanceOf[ICFGEntryNode], callee_position)
                  mddg.addEdge(calleeDDGNode, callerDDGNode)
                  if (callernode.asInstanceOf[ICFGCallNode].getCalleeSig.getSubSignature == AndroidConstants.BIND_SERVICE) {
                    bindServices += Component(ic_callee.component.apk, calleeNode.getOwner.getClassType)
                  } else if (AndroidConstants.isStartActivityForResultMethod(callernode.asInstanceOf[ICFGCallNode].getCalleeSig.getSubSignature)) {
                    forResultTargets += Component(ic_callee.component.apk, calleeNode.getOwner.getClassType)
                  }
                case _ =>
              }
            }
            icc_summary.asCallee.foreach {
              case (_, callee) =>
                callee match {
                  case irc: IntentResultCallee => irc.addTargets(forResultTargets.toSet)
                  case _ =>
                }
            }
            val rpc_summary: RPC_Summary = summaryTable.get(CHANNELS.RPC)
            rpc_summary.asCaller.foreach {
              case (_, caller) =>
                caller match {
                  case rpc: RPCCaller => rpc.addBindServices(bindServices.toSet)
                  case _ =>
                }
            }
        }
      } catch {
        case ex: Exception =>
          if (DEBUG) ex.printStackTrace()
          component.apk.reporter.error(TITLE, ex.getMessage)
      }
    }

    components.foreach { component =>
      try {
        val summaryTable = summaryMap.getOrElse(component, throw new RuntimeException("Summary table does not exist for " + component))
        val icc_summary: ICC_Summary = summaryTable.get(CHANNELS.ICC)
        icc_summary.asCaller foreach {
          case (callernode, icc_caller) =>
            allICCCallees.filter(_._2.isInstanceOf[IntentResultCallee]).filter(_._2.matchWith(icc_caller)) foreach { case (calleeNode, icc_callee) =>
              icc_callee match {
                case _: IntentResultCallee =>
                  reporter.println(component + " --icc: setResult--> " + icc_callee.asInstanceOf[IntentResultCallee].component)
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
            val rpc_callees = allRpcCallees.filter(_._2.matchWith(rpc_caller))
            rpc_callees foreach {
              case (calleenode, rpc_callee) =>
                rpc_callee match {
                  case mc: MessengerCallee =>
                    reporter.println(component + " --rpc: Messenger.send to Handler.handleMessage--> " + mc.owner)
                    val callerDDGNode = mddg.getIDDGCallArgNode(callernode.asInstanceOf[ICFGCallNode], 1)
                    val calleeDDGNode = mddg.getIDDGEntryParamNode(calleenode.asInstanceOf[ICFGEntryNode], 1)
                    mddg.addEdge(calleeDDGNode, callerDDGNode)
                  case bsc: BoundServiceCallee =>
                    reporter.println(component + " --rpc: " + bsc.sig + "--> " + bsc.component)
                    for (i <- callernode.asInstanceOf[ICFGCallNode].argNames.indices) {
                      val callerDDGNode = mddg.getIDDGCallArgNode(callernode.asInstanceOf[ICFGCallNode], i)
                      val calleeDDGNode = mddg.getIDDGEntryParamNode(calleenode.asInstanceOf[ICFGEntryNode], i)
                      mddg.addEdge(calleeDDGNode, callerDDGNode)
                    }
                  case bsrc: BoundServiceReturnCallee =>
                    reporter.println(component + " --rpc return: " + bsrc.callee_sig + "--> " + bsrc.component)
                    for (i <- calleenode.asInstanceOf[ICFGReturnNode].argNames.indices) {
                      val callerDDGNode = mddg.getIDDGExitParamNode(callernode.asInstanceOf[ICFGExitNode], i)
                      val calleeDDGNode = mddg.getIDDGReturnArgNode(calleenode.asInstanceOf[ICFGReturnNode], i)
                      mddg.addEdge(calleeDDGNode, callerDDGNode)
                    }
                    component.apk.getIDFG(component.typ) match {
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
              case (calleenode, st_callee) =>
                reporter.echo(TITLE, component + " --static field: " + sf_write.asInstanceOf[StaticFieldWrite].fqn + "--> " + st_callee.asInstanceOf[StaticFieldRead].component)
                val callerDDGNode = mddg.getIDDGNormalNode(callernode.asInstanceOf[ICFGNormalNode])
                val calleeDDGNode = mddg.getIDDGNormalNode(calleenode.asInstanceOf[ICFGNormalNode])
                mddg.addEdge(calleeDDGNode, callerDDGNode)
            }
        }

      } catch {
        case ex: Exception =>
          if (DEBUG) ex.printStackTrace()
          component.apk.reporter.error(TITLE, ex.getMessage)
      }
    }
    mddg
  }
}

case class Component(apk: ApkGlobal, typ: JawaType)

class ComponentSummaryTable(val component: Component) {
  import ComponentSummaryTable._
  
  private val table: IMap[CHANNELS.Value, CSTContent] = Map(
      CHANNELS.ICC -> new ICC_Summary,
      CHANNELS.RPC -> new RPC_Summary,
      CHANNELS.STATIC_FIELD -> new StaticField_Summary)
  
  def get[T <: CSTContent](channel: CHANNELS.Value): T = table(channel).asInstanceOf[T]
  
  
}

trait CSTContent {
  def asCaller: ISet[(ICFGNode, CSTCaller)]
  def asCallee: ISet[(ICFGNode, CSTCallee)]
}

trait CSTCaller {
  
}

trait CSTCallee {
  def matchWith(caller: CSTCaller): Boolean
}

class ICC_Summary extends CSTContent {
  private val callers: MSet[(ICFGNode, ICCCaller)] = msetEmpty
  private val callees: MSet[(ICFGNode, ICCCallee)] = msetEmpty
  def addCaller(node: ICFGNode, caller: ICCCaller): Unit = callers += ((node, caller))
  def addCallee(node: ICFGNode, callee: ICCCallee): Unit = callees += ((node, callee))
  def asCaller: ISet[(ICFGNode, CSTCaller)] = callers.toSet
  def asCallee: ISet[(ICFGNode, CSTCallee)] = callees.toSet
}

trait ICCCaller extends CSTCaller

trait ICCCallee extends CSTCallee

case class IntentCaller(component: Component, compTyp: AndroidConstants.CompType.Value, intent: Intent) extends ICCCaller

case class IntentCallee(component: Component, compTyp: AndroidConstants.CompType.Value, filter: ISet[IntentFilter], exported: Boolean) extends ICCCallee {
  def matchWith(caller: CSTCaller): Boolean = {
    caller match {
      case intent_caller: IntentCaller =>
        if((exported || component.apk.nameUri == intent_caller.component.apk.nameUri) && compTyp == intent_caller.compTyp){
          if (intent_caller.intent.explicit && !intent_caller.intent.precise) true
          else if (!intent_caller.intent.explicit && !intent_caller.intent.precise && filter.nonEmpty) true
          else if (intent_caller.intent.componentNames.contains(component.typ.name)) true
          else if (IntentHelper.findComponents(
            component.apk,
            intent_caller.intent.actions,
            intent_caller.intent.categories,
            intent_caller.intent.data,
            intent_caller.intent.types).contains(component.typ)) true
          else false
        } else false
      case _ => false
    }
  }
}

case class IntentResultCaller(component: Component) extends ICCCaller

case class IntentResultCallee(component: Component) extends ICCCallee {
  private val targetComponents: MSet[Component] = msetEmpty
  def addTargets(comps: ISet[Component]): Unit = targetComponents ++= comps
  def getTargets: ISet[Component] = targetComponents.toSet
  override def matchWith(caller: CSTCaller): Boolean = {
    caller match {
      case ir_caller: IntentResultCaller =>
        targetComponents.contains(ir_caller.component)
      case _ => false
    }
  }
}

class RPC_Summary extends CSTContent {
  private val callers: MSet[(ICFGNode, RPCCaller)] = msetEmpty
  private val callees: MSet[(ICFGNode, RPCCallee)] = msetEmpty
  def addCaller(node: ICFGNode, caller: RPCCaller): Unit = callers += ((node, caller))
  def addCallee(node: ICFGNode, callee: RPCCallee): Unit = callees += ((node, callee))
  def asCaller: ISet[(ICFGNode, CSTCaller)] = callers.toSet
  def asCallee: ISet[(ICFGNode, CSTCallee)] = callees.toSet
}

trait RPCCaller extends CSTCaller {
  private val bindServices: MSet[Component] = msetEmpty
  def addBindServices(s: ISet[Component]): Unit = bindServices ++= s
  def getBindServices: ISet[Component] = bindServices.toSet
}

trait RPCCallee extends CSTCallee

case class BoundServiceCaller(component: Component, sig: Signature) extends RPCCaller

case class BoundServiceCallee(component: Component, sig: Signature, allow_remote: Boolean) extends RPCCallee {
  def matchWith(caller: CSTCaller): Boolean = {
    caller match {
      case rpc_caller: BoundServiceCaller =>
        if(allow_remote) sig == rpc_caller.sig
        else component.apk.nameUri == rpc_caller.component.apk.nameUri && sig == rpc_caller.sig
      case _ => false
    }
  }
}

case class BoundServiceReturnCaller(component: Component, owner_sig: Signature, allow_remote: Boolean) extends RPCCaller
case class BoundServiceReturnCallee(component: Component, callee_sig: Signature) extends RPCCallee {
  override def matchWith(caller: CSTCaller): Boolean = {
    caller match {
      case rpc_caller: BoundServiceReturnCaller =>
        if(rpc_caller.allow_remote) callee_sig == rpc_caller.owner_sig
        else rpc_caller.component.apk.nameUri == component.apk.nameUri && callee_sig == rpc_caller.owner_sig
      case _ => false
    }
  }
}

case class MessengerCaller(component: Component, sig: Signature) extends RPCCaller

case class MessengerCallee(owner: Component, sig: Signature) extends RPCCallee {
  def matchWith(caller: CSTCaller): Boolean = {
    caller match {
      case rpc_caller: MessengerCaller =>
        rpc_caller.getBindServices.contains(owner)
      case _ => false
    }
  }
}

class StaticField_Summary extends CSTContent {
  private val callers: MSet[(ICFGNode, StaticFieldWrite)] = msetEmpty
  private val callees: MSet[(ICFGNode, StaticFieldRead)] = msetEmpty
  def addCaller(node: ICFGNode, caller: StaticFieldWrite): Unit = callers += ((node, caller))
  def addCallee(node: ICFGNode, callee: StaticFieldRead): Unit = callees += ((node, callee))
  def asCaller: ISet[(ICFGNode, CSTCaller)] = callers.toSet
  def asCallee: ISet[(ICFGNode, CSTCallee)] = callees.toSet
}

case class StaticFieldWrite(component: Component, fqn: FieldFQN) extends CSTCaller

case class StaticFieldRead(component: Component, fqn: FieldFQN) extends CSTCallee {
  def matchWith(caller: CSTCaller): Boolean = {
    caller match {
      case sf_caller: StaticFieldWrite =>
        component.apk.nameUri == sf_caller.component.apk.nameUri && fqn.fqn == sf_caller.fqn.fqn
      case _ => false
    }
  }
}