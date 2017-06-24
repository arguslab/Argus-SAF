/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.pta.reachingFactsAnalysis

import org.argus.jawa.core.util._

import scala.collection.immutable.BitSet
import java.util.concurrent.TimeoutException

import org.argus.amandroid.alir.pta.reachingFactsAnalysis.model.AndroidModelCallHandler
import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.controlFlowGraph._
import org.argus.jawa.alir.dataFlowAnalysis._
import org.argus.jawa.alir.interprocedural.{CallHandler, Callee}
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, ReachingFactsAnalysisHelper, SimHeap}
import org.argus.jawa.alir.pta.summaryBasedAnalysis.SummaryManager
import org.argus.jawa.compiler.parser._
import org.argus.jawa.core._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class AndroidReachingFactsAnalysisBuilder(apk: ApkGlobal, clm: ClassLoadManager, timeout: Option[MyTimeout])(implicit factory: SimHeap) {

  import AndroidReachingFactsAnalysis._
  
  final val TITLE = "AndroidReachingFactsAnalysisBuilder"
  
  var icfg: InterProceduralControlFlowGraph[Node] = _
  val ptaresult = new PTAResult

  var currentComponent: JawaClass = _

  val sm: SummaryManager = new SummaryManager()
  sm.registerFileInternal("summaries/String.safsu")
  sm.registerFileInternal("summaries/StringBuilder.safsu")
  sm.registerFileInternal("summaries/StringBuffer.safsu")
  sm.registerFileInternal("summaries/Map.safsu")
  sm.registerFileInternal("summaries/Set.safsu")
  sm.registerFileInternal("summaries/List.safsu")
  sm.registerFileInternal("summaries/Thread.safsu")
  sm.registerFileInternal("summaries/Bundle.safsu")

  def build (
      entryPointProc: JawaMethod,
      initialFacts: ISet[RFAFact] = isetEmpty,
      initContext: Context,
      switchAsOrderedMatch: Boolean): InterProceduralDataFlowGraph = {
    currentComponent = entryPointProc.getDeclaringClass
    val gen = new Gen
    val kill = new Kill
    val callr = new Callr
    val initial: ISet[RFAFact] = isetEmpty
    val icfg = new InterProceduralControlFlowGraph[ICFGNode]
    val ip = new Ip(icfg)
    this.icfg = icfg
    icfg.collectCfgToBaseGraph(entryPointProc, initContext, isFirst = true)
    val iota: ISet[RFAFact] = initialFacts + new RFAFact(StaticFieldSlot("Analysis.RFAiota"), PTAInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown, initContext.copy))
    try {
      MonotoneDataFlowAnalysisFramework[ICFGNode, RFAFact, Context](icfg,
        forward = true, lub = true, ip, gen, kill, Some(callr), iota, initial)
    } catch {
      case te: TimeoutException =>
        apk.reporter.warning(TITLE, entryPointProc.getSignature + " " + te.getMessage)
    }
//    icfg.toDot(new PrintWriter(System.out))
    InterProceduralDataFlowGraph(icfg, ptaresult)
  }

  private def checkAndLoadClassFromHierarchy(me: JawaClass, s: ISet[RFAFact], currentNode: Node): Unit = {
    if(me.hasSuperClass){
      checkAndLoadClassFromHierarchy(me.getSuperClass, s, currentNode)
    }
    val bitset = currentNode.getLoadedClassBitSet
    if(!clm.isLoaded(me, bitset)) {
      currentNode.setLoadedClassBitSet(clm.loadClass(me, bitset))
//      val newbitset = currentNode.getLoadedClassBitSet
      if(me.declaresStaticInitializer) {
        val p = me.getStaticInitializer.get
        if(AndroidReachingFactsAnalysisConfig.resolve_static_init) {
          if(AndroidModelCallHandler.isModelCall(p)) {
            ReachingFactsAnalysisHelper.getUnknownObjectForClinit(p, currentNode.getContext)
          } else if(!this.icfg.isProcessed(p.getSignature, currentNode.getContext)) { // for normal call
            val nodes = this.icfg.collectCfgToBaseGraph(p, currentNode.getContext)
            nodes.foreach{n => n.setLoadedClassBitSet(clm.loadClass(me, bitset))}
            val clinitVirEntryContext = currentNode.getContext.copy.setContext(p.getSignature, "Entry")
            val clinitVirExitContext = currentNode.getContext.copy.setContext(p.getSignature, "Exit")
            val clinitEntry = this.icfg.getICFGEntryNode(clinitVirEntryContext)
            val clinitExit = this.icfg.getICFGExitNode(clinitVirExitContext)
            this.icfg.addEdge(currentNode, clinitEntry)
            this.icfg.addEdge(clinitExit, currentNode)
          }
        }
      }
    }
  }

  private def checkClass(recTyp: JawaType, s: ISet[RFAFact], currentNode: Node): Unit = {
    val rec = apk.getClassOrResolve(recTyp)
    checkAndLoadClassFromHierarchy(rec, s, currentNode)
  }

  /**
   * A.<clinit>() will be called under four kinds of situation: v0 = new A, A.f = v1, v2 = A.f, and A.foo()
   * also for v0 = new B where B is descendant of A, first we call A.<clinit>, later B.<clinit>.
   */
  protected def checkAndLoadClasses(a: Assignment, s: ISet[RFAFact], currentNode: Node): Unit = {
    a match {
      case as: AssignmentStatement =>
        as.lhs match {
          case ne: NameExpression =>
            val slot = ReachingFactsAnalysisHelper.getNameSlotFromNameExp(ne)
            slot match {
              case slot1: StaticFieldSlot =>
                val recTyp = JavaKnowledge.getClassTypeFromFieldFQN(slot1.fqn)
                checkClass(recTyp, s, currentNode)
              case _ =>
            }
          case _ =>
        }
        as.rhs match {
          case ne: NewExpression =>
            val typ = ne.typ
            checkClass(typ, s, currentNode)
          case ne: NameExpression =>
            val slot = ReachingFactsAnalysisHelper.getNameSlotFromNameExp(ne)
            if (slot.isInstanceOf[StaticFieldSlot]) {
              val fqn = ne.name
              val recTyp = JavaKnowledge.getClassTypeFromFieldFQN(fqn)
              checkClass(recTyp, s, currentNode)
            }
          case _ =>
        }
      case cs: CallStatement =>
        val kind = cs.kind
        if (kind == "static") {
          val recTyp = a.asInstanceOf[CallStatement].signature.getClassType
          checkClass(recTyp, s, currentNode)
        }
    }
  }

  def getExceptionFacts(a: Assignment, s: ISet[RFAFact], currentContext: Context): ISet[RFAFact] = {
    var result = isetEmpty[RFAFact]
    a match{
      case _: AssignmentStatement =>
        val thrownExcNames = ExceptionCenter.getExceptionMayThrowFromStatement(a)
        thrownExcNames.foreach{
          excName =>
            if(excName != ExceptionCenter.THROWABLE) {
              val ins = PTAInstance(excName, currentContext.copy)
              result += new RFAFact(VarSlot(ExceptionCenter.EXCEPTION_VAR_NAME), ins)
            }
        }
      case _ =>
    }
    result
  }

  protected def isInterestingAssignment(a: Assignment): Boolean = {
    a match{
      case as: AssignmentStatement =>
        as.rhs match {
          case _: CastExpression => true
          case _: ConstClassExpression => true
          case _: ExceptionExpression => true
          case _: NewExpression => true
          case _: NullExpression => true
          case _ =>
            as.kind == "object"
        }
      case _ => false
    }
  }

  class Gen extends MonotonicFunction[Node, RFAFact] {

    private def handleAssignmentStatement(s: ISet[RFAFact], a: AssignmentStatement, currentNode: Node): ISet[RFAFact] = {
      val typ = a match {
        case as: AssignmentStatement => as.typOpt
        case _ => None
      }
      var result: ISet[RFAFact] = isetEmpty
      if(isInterestingAssignment(a)) {
        val lhsOpt = a.getLhs
        val rhs = a.getRhs
        val slots: IMap[PTASlot, Boolean] = lhsOpt match {
          case Some(lhs) => ReachingFactsAnalysisHelper.processLHS(lhs, typ, currentNode.getContext, ptaresult)
          case None => imapEmpty
        }
        checkAndLoadClasses(a, s, currentNode)
        val values = ReachingFactsAnalysisHelper.processRHS(rhs, typ, currentNode.getContext, ptaresult)
        slots.foreach {
          case (slot, _) =>
            result ++= values.map{v => new RFAFact(slot, v)}
        }
        val heapUnknownFacts = ReachingFactsAnalysisHelper.getHeapUnknownFacts(rhs, currentNode.getContext, ptaresult)
        result ++= heapUnknownFacts
      }
      val exceptionFacts: ISet[RFAFact] = getExceptionFacts(a, s, currentNode.getContext)
      result ++= exceptionFacts
      result
    }

    def apply(s: ISet[RFAFact], e: Statement, currentNode: Node): ISet[RFAFact] = {
      var result: ISet[RFAFact] = isetEmpty
      e match{
        case as: AssignmentStatement =>
          result ++= handleAssignmentStatement(s, as, currentNode)
        case ta: ThrowStatement =>
          val slot = VarSlot(ta.varSymbol.varName)
          val value = s.filter(_.s == slot).map(_.v)
          result ++= value.map(new RFAFact(VarSlot(ExceptionCenter.EXCEPTION_VAR_NAME), _))
        case _ =>
      }
      result
    }
  }

  class Kill
      extends MonotonicFunction[Node, RFAFact] {

    private def handleAssignmentStatement(s: ISet[RFAFact], a: AssignmentStatement, currentNode: Node): ISet[RFAFact] = {
      val typ = a match {
        case as: AssignmentStatement => as.typOpt
        case _ => None
      }
      var result = s
      val lhsOpt = a.getLhs
      lhsOpt match {
        case Some(lhs) =>
          val slotsWithMark = ReachingFactsAnalysisHelper.processLHS(lhs, typ, currentNode.getContext, ptaresult).toSet
          for (rdf @ RFAFact(_, _) <- s) {
            //if it is a strong definition, we can kill the existing definition
            if (slotsWithMark.contains(rdf.s, true)) {
              result = result - rdf
            }
          }
        case None =>
      }

      result
    }

    def apply(s: ISet[RFAFact], e: Statement, currentNode: Node): ISet[RFAFact] = {
      e match {
        case as: AssignmentStatement => handleAssignmentStatement(s, as, currentNode)
        case _ => s
      }
    }
  }

  class Callr extends CallResolver[Node, RFAFact] {
    val pureNormalFlagMap: MMap[ICFGNode, Boolean] = mmapEmpty
    /**
     * It returns the facts for each callee entry node and caller return node
     */
    def resolveCall(s: ISet[RFAFact], cs: CallStatement, callerNode: Node): (IMap[Node, ISet[RFAFact]], ISet[RFAFact]) = {
      val callerContext = callerNode.getContext
      val sig = cs.signature
      val calleeSet = CallHandler.getCalleeSet(apk, cs, sig, callerContext, ptaresult)
      val icfgCallnode = icfg.getICFGCallNode(callerContext)
      icfgCallnode.asInstanceOf[ICFGCallNode].setCalleeSet(calleeSet.map(_.asInstanceOf[Callee]))
      val icfgReturnnode = icfg.getICFGReturnNode(callerContext)
      icfgReturnnode.asInstanceOf[ICFGReturnNode].setCalleeSet(calleeSet.map(_.asInstanceOf[Callee]))
      var calleeFactsMap: IMap[ICFGNode, ISet[RFAFact]] = imapEmpty
      var returnFacts: ISet[RFAFact] = s
      val genSet: MSet[RFAFact] = msetEmpty
      val killSet: MSet[RFAFact] = msetEmpty
      var pureNormalFlag = pureNormalFlagMap.getOrElseUpdate(callerNode, true)

      val args = (cs.recvOpt ++ cs.args).toList
      calleeSet.foreach { callee =>
        val calleeSig: Signature = callee.callee
        icfg.getCallGraph.addCall(callerNode.getOwner, calleeSig)
        val calleep = apk.getMethodOrResolve(calleeSig).get
        if(AndroidModelCallHandler.isICCCall(calleeSig) || AndroidModelCallHandler.isRPCCall(apk, currentComponent.getType, calleeSig) || AndroidModelCallHandler.isModelCall(calleep)) {
          pureNormalFlag = false
          if(AndroidModelCallHandler.isICCCall(calleeSig)) {
            // don't do anything for the ICC call now.
          } else if (AndroidModelCallHandler.isRPCCall(apk, currentComponent.getType, calleeSig)) {
            // don't do anything for the RPC call now.
          } else { // for non-ICC-RPC model call
            returnFacts = AndroidModelCallHandler.doModelCall(sm, s, calleep, cs.lhsOpt.map(_.lhs.varName), cs.recvOpt, cs.args, callerContext)
            if(returnFacts.diff(s).isEmpty) {
              val (g, k) = AndroidModelCallHandler.doModelCallOld(ptaresult, calleep, args, cs.lhsOpt.map(_.lhs.varName), callerContext)
              genSet ++= g
              killSet ++= k
            } else {
              return (calleeFactsMap, returnFacts)
            }
          }
        } else {
          // for normal call
          if (calleep.isConcrete) {
            if (!icfg.isProcessed(calleeSig, callerContext)) {
              icfg.collectCfgToBaseGraph[String](calleep, callerContext, isFirst = false)
              icfg.extendGraph(calleeSig, callerContext)
            }
            val factsForCallee = getFactsForCallee(s, cs, calleep, callerContext)
            killSet ++= factsForCallee
            calleeFactsMap += (icfg.entryNode(calleeSig, callerContext) -> callee.mapFactsToCallee(factsForCallee, args, (calleep.thisOpt ++ calleep.getParamNames).toList, factory))
          }
        }
      }
      if(pureNormalFlag) {
        if(icfg.hasEdge(icfgCallnode, icfgReturnnode)) {
          icfg.deleteEdge(icfgCallnode, icfgReturnnode)
        }
      } else pureNormalFlagMap(callerNode) = pureNormalFlag

      cs.lhsOpt match {
        case Some(lhs) =>
          val slotsWithMark = ReachingFactsAnalysisHelper.processLHS(lhs, None, callerContext, ptaresult).toSet
          for (rdf <- s) {
            //if it is a strong definition, we can kill the existing definition
            if (slotsWithMark.contains(rdf.s, true)) {
              killSet += rdf
            }
          }
        case None =>
      }

      returnFacts = returnFacts -- killSet ++ genSet
      (calleeFactsMap, returnFacts)
    }

    private def getFactsForCallee(s: ISet[RFAFact], cs: CallStatement, callee: JawaMethod, callerContext: Context): ISet[RFAFact] = {
      val calleeFacts = msetEmpty[RFAFact]
      calleeFacts ++= ReachingFactsAnalysisHelper.getGlobalFacts(s)
      val args = (cs.recvOpt ++ cs.args).toList
      for(i <- args.indices) {
        val arg = args(i)
        val slot = VarSlot(arg)
        val value = ptaresult.pointsToSet(after = false, callerContext, slot)
        calleeFacts ++= value.map { r => new RFAFact(VarSlot(slot.varName), r) }
        val instnums = value.map(factory.getInstanceNum)
        calleeFacts ++= ReachingFactsAnalysisHelper.getRelatedHeapFacts(instnums, s)
      }
      calleeFacts.toSet
    }

    private def isReturnJump(loc: Location): Boolean = {
      loc.statement.isInstanceOf[ReturnStatement]
    }

    def getAndMapFactsForCaller(calleeS: ISet[RFAFact], callerNode: Node, calleeExitNode: Node): ISet[RFAFact] ={
      val result = msetEmpty[RFAFact]
      val kill = msetEmpty[RFAFact]
      /**
       * adding global facts to result
       */
      result ++= ReachingFactsAnalysisHelper.getGlobalFacts(calleeS)

      val calleeMethod = apk.getMethod(calleeExitNode.getOwner).get
      val paramSlots: IList[VarSlot] = (calleeMethod.thisOpt ++ calleeMethod.getParamNames).map(VarSlot).toList

      callerNode match {
        case crn: ICFGReturnNode =>
          val calleeVarFacts = calleeS.filter(_.s.isInstanceOf[VarSlot]).map{f=>(f.s.asInstanceOf[VarSlot], f.v)}
          val cs = apk.getMethod(crn.getOwner).get.getBody.resolvedBody.locations(crn.locIndex).statement.asInstanceOf[CallStatement]
          val lhsSlotOpt: Option[VarSlot] = cs.lhsOpt.map{lhs=>VarSlot(lhs.lhs.varName)}
          var retSlotOpt: Option[VarSlot] = None
          calleeMethod.getBody.resolvedBody.locations.foreach { loc=>
            if(isReturnJump(loc)){
              val rj = loc.statement.asInstanceOf[ReturnStatement]
              rj.varOpt match{
                case Some(n) => retSlotOpt =  Some(VarSlot(n.varName))
                case None =>
              }
            }
          }
          val argSlots = (cs.recvOpt ++ cs.args).toList.map(VarSlot)
          for(i <- argSlots.indices) {
            val argSlot = argSlots(i)
            var values: ISet[Instance] = isetEmpty
            calleeVarFacts.foreach{
              case (s, v) =>
                if(paramSlots.isDefinedAt(i) && paramSlots(i) == s)
                  values += v
            }
            result ++= values.map(v=> new RFAFact(argSlot, v))
            val insnums = values.map(factory.getInstanceNum)
            result ++= ReachingFactsAnalysisHelper.getRelatedHeapFacts(insnums, calleeS)
          }
          // kill the strong update for caller return node
          cs.lhsOpt match {
            case Some(lhs) =>
              val slotsWithMark = ReachingFactsAnalysisHelper.processLHS(lhs, None, callerNode.getContext, ptaresult).toSet
              for (rdf <- result) {
                //if it is a strong definition, we can kill the existing definition
                if (slotsWithMark.exists{case (s, st) => s.getId == rdf.s.getId && st}) {
                  kill += rdf
                }
              }
            case None =>
          }

          lhsSlotOpt.foreach { lhsSlot =>
            var values: ISet[Instance] = isetEmpty
            retSlotOpt.foreach {
              retSlot =>
                calleeVarFacts.foreach{
                  case (s, v) =>
                    if(s == retSlot){
                      values += v
                    }
                }
            }
            result ++= values.map(v => new RFAFact(lhsSlot, v))
            val insnums = values.map(factory.getInstanceNum)
            result ++= ReachingFactsAnalysisHelper.getRelatedHeapFacts(insnums, calleeS)
          }
        case _: ICFGNode =>
      }
      /**
       * update pstresult with caller's return node and it's points-to info
       */
      result.toSet -- kill
    }
  }

  class Ip(icfg: InterProceduralControlFlowGraph[ICFGNode]) extends InterIngredientProvider[RFAFact](apk, icfg) {

    override def preProcess(node: ICFGNode, statement: Statement, s: ISet[RFAFact]): Unit = {
      statement match {
        case a: AssignmentStatement =>
          ReachingFactsAnalysisHelper.updatePTAResultRHS(a.rhs, a.typOpt, node.getContext, s, ptaresult)
          ReachingFactsAnalysisHelper.updatePTAResultLHS(a.lhs, node.getContext, s, ptaresult)
        case _: EmptyStatement =>
        case m: MonitorStatement =>
          ReachingFactsAnalysisHelper.updatePTAResultVar(m.varSymbol.varName, node.getContext, s, ptaresult, after = false)
        case j: Jump =>
          j match {
            case cs: CallStatement =>
              ReachingFactsAnalysisHelper.updatePTAResultCallJump(cs, node.getContext, s, ptaresult)
            case _: GotoStatement =>
            case is: IfStatement =>
              ReachingFactsAnalysisHelper.updatePTAResultExp(is.cond, None, node.getContext, s, ptaresult)
            case rs: ReturnStatement =>
              rs.varOpt match {
                case Some(v) =>
                  ReachingFactsAnalysisHelper.updatePTAResultVar(v.varName, node.getContext, s, ptaresult, after = false)
                case None =>
              }
            case ss: SwitchStatement =>
              ReachingFactsAnalysisHelper.updatePTAResultVar(ss.condition.varName, node.getContext, s, ptaresult, after = false)
          }
        case t: ThrowStatement =>
          ReachingFactsAnalysisHelper.updatePTAResultVar(t.varSymbol.varName, node.getContext, s, ptaresult, after = false)
      }
    }

    override def postProcess(node: ICFGNode, s: ISet[RFAFact]): Unit = {
    }

    override def onPreVisitNode(node: ICFGNode, preds: CSet[ICFGNode]): Unit = {
      val bitset = if(preds.nonEmpty)preds.map{_.getLoadedClassBitSet}.reduce{ (x, y) => x.intersect(y)} else BitSet.empty
      node.setLoadedClassBitSet(bitset)
    }

    override def onPostVisitNode(node: ICFGNode, succs: CSet[ICFGNode]): Unit = {
      timeout foreach (_.isTimeoutThrow())
    }
  }
  
}



/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object AndroidReachingFactsAnalysis {
  type Node = ICFGNode
  type Result = MonotoneDataFlowAnalysisResult[Node, RFAFact]
  def apply(
      apk: ApkGlobal,
      entryPointProc: JawaMethod,
      initialFacts: ISet[RFAFact] = isetEmpty,
      clm: ClassLoadManager,
      initContext: Context,
      switchAsOrderedMatch: Boolean = false,
      timeout: Option[MyTimeout])(implicit factory: SimHeap): InterProceduralDataFlowGraph
    = new AndroidReachingFactsAnalysisBuilder(apk, clm, timeout).build(entryPointProc, initialFacts, initContext, switchAsOrderedMatch)
}
