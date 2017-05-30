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
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, RFAFactFactory, ReachingFactsAnalysisHelper}
import org.argus.jawa.compiler.parser._
import org.argus.jawa.core._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class AndroidReachingFactsAnalysisBuilder(apk: ApkGlobal, clm: ClassLoadManager, timeout: Option[MyTimeout])(implicit factory: RFAFactFactory) {

  import AndroidReachingFactsAnalysis._
  
  final val TITLE = "AndroidReachingFactsAnalysisBuilder"
  
  var icfg: InterProceduralControlFlowGraph[Node] = _
  val ptaresult = new PTAResult
  val needtoremove: MSet[(Context, RFAFact)] = msetEmpty

  var currentComponent: JawaClass = _

  def build (
      entryPointProc: JawaMethod,
      initialFacts: ISet[RFAFact] = isetEmpty,
      initContext: Context,
      switchAsOrderedMatch: Boolean): InterProceduralDataFlowGraph = {
    currentComponent = entryPointProc.getDeclaringClass
    val gen = new Gen
    val kill = new Kill
    val callr = new Callr
    val mbp = new Mbp
    val initial: ISet[RFAFact] = isetEmpty
    val icfg = new InterProceduralControlFlowGraph[ICFGNode]
    val np = new Np(icfg)
    this.icfg = icfg
    icfg.collectCfgToBaseGraph(entryPointProc, initContext, isFirst = true)
    val iota: ISet[RFAFact] = initialFacts + new RFAFact(StaticFieldSlot(FieldFQN(new JawaType("Analysis"), "RFAiota", JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)), PTAInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown, initContext.copy, isNull_ = false))
    try {
      MonotoneDataFlowAnalysisFramework[ICFGNode, RFAFact, Context](icfg,
        forward = true, lub = true, mbp, np, gen, kill, Some(callr), iota, initial)
    } catch {
      case te: TimeoutException =>
        apk.reporter.warning(TITLE, entryPointProc.getSignature + " " + te.getMessage)
    }
//    icfg.toDot(new PrintWriter(System.out))
    ptaresult.addEntryPoint(entryPointProc.getSignature)
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
        val typ = as.typOpt
        as.lhs match {
          case ne: NameExpression =>
            val slot = ReachingFactsAnalysisHelper.getNameSlotFromNameExp(ne, typ, isBase = false, isArg = false, apk)
            slot match {
              case slot1: StaticFieldSlot =>
                val recTyp = slot1.fqn.owner
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
            val slot = ReachingFactsAnalysisHelper.getNameSlotFromNameExp(ne, typ, isBase = false, isArg = false, apk)
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
              val ins = PTAInstance(excName, currentContext.copy, isNull_ = false)
              result += new RFAFact(VarSlot(ExceptionCenter.EXCEPTION_VAR_NAME, isBase = false, isArg = false), ins)
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
          case Some(lhs) => ReachingFactsAnalysisHelper.processLHS(lhs, typ, currentNode.getContext, ptaresult, apk)
          case None => imapEmpty
        }
        checkAndLoadClasses(a, s, currentNode)
        val values = ReachingFactsAnalysisHelper.processRHS(rhs, typ, currentNode.getContext, ptaresult, apk)
        slots.foreach {
          case (slot, _) =>
            result ++= values.map{v => new RFAFact(slot, v)}
        }
        val heapUnknownFacts = ReachingFactsAnalysisHelper.getHeapUnknownFacts(rhs, currentNode.getContext, ptaresult)
        result ++= heapUnknownFacts
      }
      val exceptionFacts: ISet[RFAFact] = getExceptionFacts(a, s, currentNode.getContext)
      result ++= exceptionFacts
      needtoremove.foreach{
        case (c, f) =>
          ptaresult.removeInstance(f.s, c, f.v)
      }
      needtoremove.clear
      result
    }

    def apply(s: ISet[RFAFact], e: Statement, currentNode: Node): ISet[RFAFact] = {
      var result: ISet[RFAFact] = isetEmpty
      e match{
        case as: AssignmentStatement =>
          result ++= handleAssignmentStatement(s, as, currentNode)
        case ta: ThrowStatement =>
          val slot = VarSlot(ta.varSymbol.varName, isBase = false, isArg = false)
          val value = s.filter(_.s == slot).map(_.v)
          result ++= value.map(new RFAFact(VarSlot(ExceptionCenter.EXCEPTION_VAR_NAME, isBase = false, isArg = false), _))
        case _ =>
      }
      result.foreach{ f =>
        ptaresult.addInstance(f.s, currentNode.getContext, f.v)
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
      ReachingFactsAnalysisHelper.updatePTAResultRHS(a.getRhs, typ, currentNode.getContext, s, ptaresult, apk)
      lhsOpt match {
        case Some(lhs) =>
          ReachingFactsAnalysisHelper.updatePTAResultLHS(lhs, currentNode.getContext, s, ptaresult)
          val slotsWithMark = ReachingFactsAnalysisHelper.processLHS(lhs, typ, currentNode.getContext, ptaresult, apk).toSet
          for (rdf @ RFAFact(_, _) <- s) {
            //if it is a strong definition, we can kill the existing definition
            if (slotsWithMark.contains(rdf.s, true)) {
              needtoremove += ((currentNode.getContext, rdf))
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
  
  class Mbp extends MethodBodyProvider {
    def getBody(sig: Signature): ResolvedBody = {
      apk.getMethod(sig).get.getBody.resolvedBody
    }
  }
  
  class Callr extends CallResolver[Node, RFAFact] {
    val pureNormalFlagMap: MMap[ICFGNode, Boolean] = mmapEmpty
    /**
     * It returns the facts for each callee entry node and caller return node
     */
    def resolveCall(s: ISet[RFAFact], cs: CallStatement, callerNode: Node): (IMap[Node, ISet[RFAFact]], ISet[RFAFact]) = {
      val callerContext = callerNode.getContext
      ReachingFactsAnalysisHelper.updatePTAResultCallJump(cs, callerContext, s, ptaresult)
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
            val (g, k) = AndroidModelCallHandler.doModelCall(ptaresult, calleep, args, cs.lhsOpt.map(_.lhs.varName), callerContext)
            genSet ++= g
            killSet ++= k
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
      
      /**
       * update ptaresult with each callee params and return var's points-to info
       */
      calleeFactsMap foreach { case (n, facts) =>
        facts foreach {
          f =>
            if(!f.s.isInstanceOf[StaticFieldSlot])
              ptaresult.addInstance(f.s, n.getContext, f.v)
        }
      }
      cs.lhsOpt match {
        case Some(lhs) =>
          val slotsWithMark = ReachingFactsAnalysisHelper.processLHS(lhs, None, callerContext, ptaresult, apk).toSet
          for (rdf <- s) {
            //if it is a strong definition, we can kill the existing definition
            if (slotsWithMark.contains(rdf.s, true)) {
              killSet += rdf
            }
          }
        case None =>
      }

      val gen: ISet[RFAFact] = genSet.map {
        case rfa @ RFAFact(_, v) =>
          val news = rfa.s match {
            case VarSlot(a, b, true) => VarSlot(a, b, isArg = false)
            case a => a
          }
          RFAFact(factory.getSlotNum(news), v)
      }.toSet
      val kill: ISet[RFAFact] = killSet.map {
        case rfa @ RFAFact(_, v) =>
          val news = rfa.s match {
            case VarSlot(a, b, true) => VarSlot(a, b, isArg = false)
            case a => a
          }
          RFAFact(factory.getSlotNum(news), v)
      }.toSet
      
      returnFacts = returnFacts -- kill ++ gen
      genSet foreach (f => ptaresult.addInstance(f.s, callerContext, f.v))
      (calleeFactsMap, returnFacts)
    }
    
    private def getFactsForCallee(s: ISet[RFAFact], cs: CallStatement, callee: JawaMethod, callerContext: Context): ISet[RFAFact] = {
      val calleeFacts = msetEmpty[RFAFact]
      calleeFacts ++= ReachingFactsAnalysisHelper.getGlobalFacts(s)
      val args = (cs.recvOpt ++ cs.args).toList
      for(i <- args.indices) {
        val arg = args(i)
        val slot = VarSlot(arg, isBase = false, isArg = true)
        val value = ptaresult.pointsToSet(slot, callerContext)
//        if (!cs.isStatic && i == 0) {
//          value = value.filter { r =>
//            !r.isNull && !r.isUnknown && shouldPass(r, callee, typ)
//          }
//        }
        calleeFacts ++= value.map { r => new RFAFact(VarSlot(slot.varName, isBase = false, isArg = false), r) }
        val instnums = value.map(factory.getInstanceNum)
        calleeFacts ++= ReachingFactsAnalysisHelper.getRelatedHeapFacts(instnums, s)
      }
      calleeFacts.toSet
    }
    
    /**
     * return true if the given recv Instance should pass to the given callee
     */
//    private def shouldPass(recvIns: Instance, calleeProc: JawaMethod, typ: String): Boolean = {
//      val recRecv = apk.getClassOrResolve(recvIns.typ)
//      val recCallee = calleeProc.getDeclaringClass
//      var tmpRec = recRecv
//      if(typ == "direct" || typ == "super" ){
//        true
//      } else {
//        while(tmpRec.hasSuperClass){
//          if(tmpRec == recCallee) return true
//          else if(tmpRec.declaresMethod(calleeProc.getSubSignature)) return false
//          else tmpRec = apk.getClassOrResolve(tmpRec.getSuperClass)
//        }
//        if(tmpRec == recCallee) true
//        else {
//          apk.reporter.echo(TITLE, "Given recvIns: " + recvIns + " and calleeProc: " + calleeProc + " is not in the Same hierarchy.")
//          false
//        }
//      }
//    }
    
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
      val paramSlots: IList[VarSlot] = (calleeMethod.thisOpt ++ calleeMethod.getParamNames).map(VarSlot(_, isBase = false, isArg = false)).toList
      /**
       *  update ptaresult with all params points-to info and it's related heap points-to info.
       */
      paramSlots.foreach{
        pSlot =>
          val insnums = calleeS.filter { fact => pSlot == fact.s } map (_.ins)
          val heapfacts = ReachingFactsAnalysisHelper.getRelatedHeapFacts(insnums, calleeS)
          val value = insnums.map(factory.getInstance)
          ptaresult.addInstances(pSlot, calleeExitNode.getContext, value)
          heapfacts foreach {
            case rfa @ RFAFact(_, _) => ptaresult.addInstance(rfa.s, calleeExitNode.getContext, rfa.v)
          }
      }
      
      callerNode match {
        case crn: ICFGReturnNode =>
          val calleeVarFacts = calleeS.filter(_.s.isInstanceOf[VarSlot]).map{f=>(f.s.asInstanceOf[VarSlot], f.v)}
          val cs = apk.getMethod(crn.getOwner).get.getBody.resolvedBody.locations(crn.locIndex).statement.asInstanceOf[CallStatement]
          val lhsSlotOpt: Option[VarSlot] = cs.lhsOpt.map{lhs=>VarSlot(lhs.lhs.varName, isBase = false, isArg = false)}
          var retSlotOpt: Option[VarSlot] = None
          calleeMethod.getBody.resolvedBody.locations.foreach { loc=>
            if(isReturnJump(loc)){
              val rj = loc.statement.asInstanceOf[ReturnStatement]
              rj.varOpt match{
                case Some(n) => retSlotOpt =  Some(VarSlot(n.varName, isBase = false, isArg = false))
                case None =>
              }
            }
          }
          val argSlots = (cs.recvOpt ++ cs.args).toList.map(VarSlot(_, isBase = false, isArg = true))
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
              val slotsWithMark = ReachingFactsAnalysisHelper.processLHS(lhs, None, callerNode.getContext, ptaresult, apk).toSet
              for (rdf @ RFAFact(_, value) <- result) {
                //if it is a strong definition, we can kill the existing definition
                if (slotsWithMark.exists{case (s, st) => s.getId == rdf.s.getId && st}) {
                  val news = rdf.s match {
                    case VarSlot(a, b, true) => VarSlot(a, b, isArg = false)
                    case a => a
                  }
                  kill += RFAFact(factory.getSlotNum(news), value)
                }
              }
            case None =>
          }

          lhsSlotOpt.foreach {
            lhsSlot =>
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
      result.map {
        rFact =>
          if(!rFact.s.isInstanceOf[StaticFieldSlot]){
            ptaresult.addInstance(rFact.s, callerNode.getContext, rFact.v)
          }
          rFact.s match{
            case VarSlot(a, b, true) => new RFAFact(VarSlot(a, b, isArg = false), rFact.v)
            case _ => rFact
          }
      }.toSet -- kill
    }
  }

  class Np(icfg: InterProceduralControlFlowGraph[ICFGNode]) extends InterNodeProvider[RFAFact](icfg) {
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
      timeout: Option[MyTimeout])(implicit factory: RFAFactFactory): InterProceduralDataFlowGraph
    = new AndroidReachingFactsAnalysisBuilder(apk, clm, timeout).build(entryPointProc, initialFacts, initContext, switchAsOrderedMatch)
}
