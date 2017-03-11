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

import org.argus.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper.IntentContent
import org.argus.amandroid.core.parser.IntentFilter
import org.argus.amandroid.core.{AndroidConstants, Apk}
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.controlFlowGraph._
import org.argus.jawa.alir.dataFlowAnalysis.InterproceduralDataFlowGraph
import org.argus.jawa.alir.pta.{Instance, VarSlot}
import org.argus.jawa.core._
import org.argus.jawa.core.util.ASTUtil
import org.sireum.pilar.ast.{ActionLocation, AssignAction, NameExp}
import org.sireum.util._

trait ComponentSummaryProvider {
  def getIntentCaller(idfg: InterproceduralDataFlowGraph, intentValue: ISet[Instance], context: Context): ISet[IntentContent]
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object ComponentSummaryTable {
  object CHANNELS extends Enumeration {
    val ICC, RPC, STATIC_FIELD = Value
  }
  
  def buildComponentSummaryTable(global: Global, apk: Apk, component: JawaType, idfg: InterproceduralDataFlowGraph, csp: ComponentSummaryProvider): ComponentSummaryTable = {
    val summaryTable: ComponentSummaryTable = new ComponentSummaryTable(component)
    // Add component as icc callee
    val filters = apk.getIntentFilterDB.getIntentFilters(component)
    val icc_summary: ICC_Summary = summaryTable.get(CHANNELS.ICC)
    icc_summary.addCallee(idfg.icfg.entryNode, IntentCallee(apk, component, apk.getComponentType(component).get, filters))
    
    val rpcs = apk.getRpcMethods(component)
    val rpc_summary: RPC_Summary = summaryTable.get(CHANNELS.RPC)

    val sf_summary: StaticField_Summary = summaryTable.get(CHANNELS.STATIC_FIELD)

    // Collect info from idfg for component as icc caller or rpc caller or others
    idfg.icfg.nodes.filter(n => apk.getEnvMap(component)._1 != n.getOwner) foreach {
      case nn: ICFGNormalNode =>
        val method = global.getMethod(nn.getOwner).get
        method.getBody.location(nn.context.getLocUri) match {
          case loc: ActionLocation if loc.action.isInstanceOf[AssignAction] =>
            val typ = ASTUtil.getType(loc.action.asInstanceOf[AssignAction])
            val lhss = PilarAstHelper.getLHSs(loc.action.asInstanceOf[AssignAction])
            val rhss = PilarAstHelper.getRHSs(loc.action.asInstanceOf[AssignAction])
            lhss.head match {
              case ne: NameExp =>
                if (ne.name.name.startsWith("@@")) {
                  sf_summary.addCaller(nn, StaticFieldWrite(new FieldFQN(ne.name.name.replace("@@", ""), typ.get)))
                }
              case _ =>
            }
            rhss.head match {
              case ne: NameExp =>
                if (ne.name.name.startsWith("@@")) {
                  sf_summary.addCallee(nn, StaticFieldRead(new FieldFQN(ne.name.name.replace("@@", ""), typ.get)))
                }
              case _ =>
            }
          case _ =>
        }
      case en: ICFGEntryNode =>
        // Add onActivityResult as icc callee
        if(global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(en.getOwner.getClassType, new JawaType("android.app.Activity"))
          && en.getOwner.getSubSignature == "onActivityResult:(IILandroid/content/Intent;)V") {
          icc_summary.addCallee(en, IntentResultCallee(en.getOwner.getClassType))
        }
        rpcs.filter(rpc => rpc == en.context.getMethodSig).foreach {
          rpc =>
            // Add handleMessage as rpc callee
            if(global.getClassHierarchy.isClassRecursivelySubClassOf(rpc.classTyp, new JawaType("android.os.Handler"))
              && rpc.getSubSignature == "handleMessage:(Landroid/os/Message;)V") {
              rpc_summary.addCallee(en, MessengerCallee(component, rpc))
            } else {
              rpc_summary.addCallee(en, BoundServiceCallee(rpc))
            }
        }
      case cn: ICFGCallNode =>
        val callees = cn.getCalleeSet
        callees foreach {
          callee =>
            val calleeSig = callee.callee
            val ptsmap = idfg.ptaresult.getPTSMap(cn.context)
            if (AndroidConstants.isIccMethod(calleeSig.getSubSignature)) {
              // add icc call as icc caller
              val callTyp = AndroidConstants.getIccCallType(calleeSig.getSubSignature)
              val intentSlot = VarSlot(cn.argNames(1), isBase = false, isArg = true) // FIXME later
              val intentValue: ISet[Instance] = ptsmap.getOrElse(intentSlot, isetEmpty)
              val intentcontents = csp.getIntentCaller(idfg, intentValue, cn.context)
              intentcontents foreach {
                intentcontent =>
                  icc_summary.addCaller(cn, IntentCaller(callTyp, intentcontent))
              }
            }
            if(global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(calleeSig.getClassType, new JawaType("android.app.Activity"))
              && AndroidConstants.isSetResult(calleeSig.getSubSignature)) {
              // add setResult as icc caller
              icc_summary.addCaller(cn, IntentResultCaller(component))
            }
            if(global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(calleeSig.getClassType, new JawaType("android.os.Messenger"))
              && calleeSig.getSubSignature == "send:(Landroid/os/Message;)V") {
              val rpc_summary: RPC_Summary = summaryTable.get(CHANNELS.RPC)
              rpc_summary.addCaller(cn, MessengerCaller(calleeSig))
            } else if(calleeSig.getClassType.baseType.unknown) {
              apk.getRpcMethods.foreach { sig =>
                if(sig.getSubSignature == calleeSig.getSubSignature) {
                  val calleeTyp = calleeSig.classTyp.removeUnknown()
                  val calleeCls = global.getClassOrResolve(calleeTyp)
                  if((calleeCls.isInterface && global.getClassHierarchy.getAllImplementersOf(calleeTyp).contains(sig.classTyp))
                    || (!calleeCls.isInterface && global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(sig.classTyp, calleeTyp))) {
                    val rpc_summary: RPC_Summary = summaryTable.get(CHANNELS.RPC)
                    rpc_summary.addCaller(cn, BoundServiceCaller(sig))
                  }
                }
              }
            } else {
              if(apk.getRpcMethods.contains(calleeSig))
                rpc_summary.addCaller(cn, BoundServiceCaller(calleeSig))
            }

        }
      case en: ICFGExitNode =>
        rpcs.filter(rpc => rpc == en.context.getMethodSig).foreach {
          rpc =>
            if(rpc.getReturnType != new JawaType("void")) {
              // Add return node as rpc callee
              rpc_summary.addCaller(en, BoundServiceReturnCaller(rpc))
            }
        }
      case rn: ICFGReturnNode =>
        val callees = rn.getCalleeSet
        callees foreach {
          callee =>
            val calleeSig = callee.callee
            if(calleeSig.getClassType.baseType.unknown) {
              apk.getRpcMethods.foreach { sig =>
                if(sig.getSubSignature == calleeSig.getSubSignature) {
                  val calleeTyp = calleeSig.classTyp.removeUnknown()
                  val calleeCls = global.getClassOrResolve(calleeTyp)
                  if((calleeCls.isInterface && global.getClassHierarchy.getAllImplementersOf(calleeTyp).contains(sig.classTyp))
                    || (!calleeCls.isInterface && global.getClassHierarchy.isClassRecursivelySubClassOfIncluding(sig.classTyp, calleeTyp))) {
                    val rpc_summary: RPC_Summary = summaryTable.get(CHANNELS.RPC)
                    rpc_summary.addCallee(rn, BoundServiceReturnCallee(sig))
                  }
                }
              }
            } else {
              if(apk.getRpcMethods.contains(calleeSig))
                rpc_summary.addCallee(rn, BoundServiceReturnCallee(calleeSig))
            }

        }
      case _ =>
    }
    summaryTable
  }
}

class ComponentSummaryTable(val component: JawaType) {
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

case class IntentCaller(compTyp: AndroidConstants.CompType.Value, intent: IntentContent) extends ICCCaller

case class IntentCallee(apk: Apk, component: JawaType, compTyp: AndroidConstants.CompType.Value, filter: ISet[IntentFilter]) extends ICCCallee {
  def matchWith(caller: CSTCaller): Boolean = {
    caller match {
      case intent_caller: IntentCaller =>
        if(compTyp == intent_caller.compTyp){
          if (!intent_caller.intent.preciseExplicit) true
          else if (!intent_caller.intent.preciseImplicit && filter.nonEmpty) true
          else if (intent_caller.intent.componentNames.contains(component.name)) true
          else if (IntentHelper.findComponents(
              apk, 
              intent_caller.intent.actions,
              intent_caller.intent.categories,
              intent_caller.intent.datas,
              intent_caller.intent.types).contains(component)) true
          else false
        } else false
      case _ => false
    }
  }
}

case class IntentResultCaller(component: JawaType) extends ICCCaller

case class IntentResultCallee(component: JawaType) extends ICCCallee {
  private val targetComponents: MSet[JawaType] = msetEmpty
  def addTargets(comps: ISet[JawaType]): Unit = targetComponents ++= comps
  def getTargets: ISet[JawaType] = targetComponents.toSet
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
  private val bindServices: MSet[JawaType] = msetEmpty
  def addBindServices(s: ISet[JawaType]): Unit = bindServices ++= s
  def getBindServices: ISet[JawaType] = bindServices.toSet
}

trait RPCCallee extends CSTCallee

case class BoundServiceCaller(sig: Signature) extends RPCCaller

case class BoundServiceCallee(sig: Signature) extends RPCCallee {
  def matchWith(caller: CSTCaller): Boolean = {
    caller match {
      case rpc_caller: BoundServiceCaller =>
        sig == rpc_caller.sig
      case _ => false
    }
  }
}

case class BoundServiceReturnCaller(owner_sig: Signature) extends RPCCaller
case class BoundServiceReturnCallee(callee_sig: Signature) extends RPCCallee {
  override def matchWith(caller: CSTCaller): Boolean = {
    caller match {
      case rpc_caller: BoundServiceReturnCaller =>
        callee_sig == rpc_caller.owner_sig
      case _ => false
    }
  }
}

case class MessengerCaller(sig: Signature) extends RPCCaller

case class MessengerCallee(owner: JawaType, sig: Signature) extends RPCCallee {
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

case class StaticFieldWrite(fqn: FieldFQN) extends CSTCaller

case class StaticFieldRead(fqn: FieldFQN) extends CSTCallee {
  def matchWith(caller: CSTCaller): Boolean = {
    caller match {
      case sf_caller: StaticFieldWrite =>
        fqn.fqn == sf_caller.fqn.fqn
      case _ => false
    }
  }
}

//class Storage_Summary extends CSTContent {
//  private val callers: MSet[(ICFGNode, StorageCaller)] = msetEmpty
//  private val callees: MSet[(ICFGNode, StorageCallee)] = msetEmpty
//  def addCaller(node: ICFGNode, caller: StorageCaller): Unit = callers += ((node, caller))
//  def addCallee(node: ICFGNode, callee: StorageCallee): Unit = callees += ((node, callee))
//  def asCaller: ISet[(ICFGNode, CSTCaller)] = callers.toSet
//  def asCallee: ISet[(ICFGNode, CSTCallee)] = callees.toSet
//}
//
//case class StorageCaller() extends CSTCaller
//
//case class StorageCallee() extends CSTCallee {
//  def matchWith(caller: CSTCaller): Boolean = {
//    true
//  }
//}
