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

import org.sireum.util._
import org.sireum.pilar.ast._

import scala.collection.immutable.BitSet
import org.sireum.pilar.symbol.ProcedureSymbolTable
import java.util.concurrent.TimeoutException

import org.argus.amandroid.core.ApkGlobal
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.controlFlowGraph._
import org.argus.jawa.alir.dataFlowAnalysis._
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, RFAFactFactory, ReachingFactsAnalysisHelper}
import org.argus.jawa.core.util.{ASTUtil, MyTimeout}
import org.argus.jawa.core._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class AndroidReachingFactsAnalysisBuilder(apk: ApkGlobal, clm: ClassLoadManager, timeout: Option[MyTimeout])(implicit factory: RFAFactFactory) {
  
  final val TITLE = "AndroidReachingFactsAnalysisBuilder"
  
  var icfg: InterproceduralControlFlowGraph[ICFGNode] = _
  val ptaresult = new PTAResult
  val needtoremove: MSet[(Context, RFAFact)] = msetEmpty

  var currentComponent: JawaClass = _

  def build (
      entryPointProc: JawaMethod,
      initialFacts: ISet[RFAFact] = isetEmpty,
      initContext: Context,
      switchAsOrderedMatch: Boolean): InterproceduralDataFlowGraph = {
    currentComponent = entryPointProc.getDeclaringClass
    val gen = new Gen
    val kill = new Kill
    val callr = new Callr
    val ppr = new Pstr
    val nl = new NodeL
    val initial: ISet[RFAFact] = isetEmpty
    val icfg = new InterproceduralControlFlowGraph[ICFGNode]
    this.icfg = icfg
    icfg.collectCfgToBaseGraph(entryPointProc, initContext, isFirst = true)
    val iota: ISet[RFAFact] = initialFacts + new RFAFact(StaticFieldSlot(FieldFQN(new JawaType("Analysis"), "RFAiota", JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)), PTAInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown, initContext.copy, isNull_ = false))
    try {
      InterproceduralMonotoneDataFlowAnalysisFramework[RFAFact](icfg,
        true, true, false, AndroidReachingFactsAnalysisConfig.parallel, gen, kill, callr, ppr, iota, initial, switchAsOrderedMatch, Some(nl))
    } catch {
      case te: TimeoutException =>
        apk.reporter.warning(TITLE, entryPointProc.getSignature + " " + te.getMessage)
    }
//    icfg.toDot(new PrintWriter(System.out))
    ptaresult.addEntryPoint(entryPointProc.getSignature)
    InterproceduralDataFlowGraph(icfg, ptaresult)
  }
  
  private def checkAndLoadClassFromHierarchy(me: JawaClass, s: ISet[RFAFact], currentNode: ICFGLocNode): Unit = {
    if(me.hasSuperClass){
      checkAndLoadClassFromHierarchy(apk.getClassOrResolve(me.getSuperClass), s, currentNode)
    }
    val bitset = currentNode.getLoadedClassBitSet
    if(!clm.isLoaded(me, bitset)) {
      currentNode.setLoadedClassBitSet(clm.loadClass(me, bitset))
//      val newbitset = currentNode.getLoadedClassBitSet
      if(me.declaresStaticInitializer) {
        val p = me.getStaticInitializer.get
        if(AndroidReachingFactsAnalysisConfig.resolve_static_init) {
          if(AndroidReachingFactsAnalysisHelper.isModelCall(p)) {
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
  
  private def checkClass(recTyp: JawaType, s: ISet[RFAFact], currentNode: ICFGLocNode): Unit = {
    val rec = apk.getClassOrResolve(recTyp)
    checkAndLoadClassFromHierarchy(rec, s, currentNode)
  }
  
  /**
   * A.<clinit>() will be called under four kinds of situation: v0 = new A, A.f = v1, v2 = A.f, and A.foo()
   * also for v0 = new B where B is descendant of A, first we call A.<clinit>, later B.<clinit>.
   */
  protected def checkAndLoadClasses(lhss: List[Exp], rhss: List[Exp], a: Assignment, s: ISet[RFAFact], currentNode: ICFGLocNode): Unit = {
    val typ = ASTUtil.getType(a)
    lhss.foreach {
      case ne: NameExp =>
        val slot = ReachingFactsAnalysisHelper.getNameSlotFromNameExp(ne, typ, isBase = false, isArg = false, apk)
        slot match {
          case slot1: StaticFieldSlot =>
            val recTyp = slot1.fqn.owner
            checkClass(recTyp, s, currentNode)
          case _ =>
        }
      case _ =>
    }
    rhss.foreach {
      case ne: NewExp =>
        var recName: ResourceUri = ""
        var dimensions = 0
        ne.typeSpec match {
          case nt: NamedTypeSpec =>
            dimensions = ne.dims.size + ne.typeFragments.size
            recName = nt.name.name
          case _ =>
        }
        val typ = new JawaType(recName, dimensions)
        checkClass(typ, s, currentNode)
      case ne: NameExp =>
        val slot = ReachingFactsAnalysisHelper.getNameSlotFromNameExp(ne, typ, isBase = false, isArg = false, apk)
        if (slot.isInstanceOf[StaticFieldSlot]) {
          val fqn = ne.name.name.replaceAll("@@", "")
          val recTyp = JavaKnowledge.getClassTypeFromFieldFQN(fqn)
          checkClass(recTyp, s, currentNode)
        }
      case _: CallExp =>
        val typ = a.getValueAnnotation("kind") match {
          case Some(exp) => exp match {
            case ne: NameExp => ne.name.name
            case _ => ""
          }
          case None => throw new RuntimeException("cannot found annotation 'kind' from: " + a)
        }
        val signature = ASTUtil.getSignature(a).get
        val recTyp = signature.getClassType
        if (typ == "static") {
          checkClass(recTyp, s, currentNode)
        }
      case _ =>
    }
  }
  
  def getExceptionFacts(a: Assignment, s: ISet[RFAFact], currentContext: Context): ISet[RFAFact] = {
    var result = isetEmpty[RFAFact]
    a match{
      case _: AssignAction =>
        val thrownExcNames = ExceptionCenter.getExceptionMayThrowFromAssignment(a)
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
    var result = false
    a match{
      case aa: AssignAction => 
        aa.rhs match {
          case _: NewExp => result = true
          case _: CastExp => result = true
          case _ =>
            a.getValueAnnotation("kind") match {
              case Some(e) => 
                e match{
                  case ne: NameExp => result = ne.name.name == "object"
                  case _ =>
                }
              case None => 
            }
        }
      case _: CallJump => result = true
      case _ =>
    }
    result
  }

  class Gen extends InterProceduralMonotonicFunction[RFAFact] {
    
    def apply(s: ISet[RFAFact], a: Assignment, currentNode: ICFGLocNode): ISet[RFAFact] = {
      val typ = ASTUtil.getType(a)
      var result: ISet[RFAFact] = isetEmpty
      if(isInterestingAssignment(a)) {
        val lhss = PilarAstHelper.getLHSs(a)
        val rhss = PilarAstHelper.getRHSs(a)
        val slots = ReachingFactsAnalysisHelper.processLHSs(lhss, typ, currentNode.getContext, ptaresult, apk)
        checkAndLoadClasses(lhss, rhss, a, s, currentNode)
        val values = ReachingFactsAnalysisHelper.processRHSs(rhss, typ, currentNode.getContext, ptaresult, apk)
        slots.foreach {
          case(i, smap) =>
              smap.foreach{
                case (slot, _) =>
                  if(values.contains(i))
                    result ++= values(i).map{v => new RFAFact(slot, v)}
              }
        }
        val heapUnknownFacts = ReachingFactsAnalysisHelper.getHeapUnknownFacts(rhss, currentNode.getContext, ptaresult)
        result ++= heapUnknownFacts
      }
      val exceptionFacts = getExceptionFacts(a, s, currentNode.getContext)
      result ++= exceptionFacts
      needtoremove.foreach{
        case (c, f) =>
          ptaresult.removeInstance(f.s, c, f.v)
      }
      needtoremove.clear
      result.foreach{
        f =>
          ptaresult.addInstance(f.s, currentNode.getContext, f.v)
      }
      result
    }

    def apply(s: ISet[RFAFact], e: Exp, currentNode: ICFGLocNode): ISet[RFAFact] = isetEmpty
    
    def apply(s: ISet[RFAFact], a: Action, currentNode: ICFGLocNode): ISet[RFAFact] = {
      var result: ISet[RFAFact] = isetEmpty
      a match{
        case ta: ThrowAction =>
          require(ta.exp.isInstanceOf[NameExp])
          val slot = VarSlot(ta.exp.asInstanceOf[NameExp].name.name, isBase = false, isArg = false)
          val value = s.filter(_.s == slot).map(_.v)
          result ++= value.map(new RFAFact(VarSlot(ExceptionCenter.EXCEPTION_VAR_NAME, isBase = false, isArg = false), _))
        case _ =>
      }
      result.foreach{
        f =>
          ptaresult.addInstance(f.s, currentNode.getContext, f.v)
      }
      result
    }
  }

  class Kill
      extends InterProceduralMonotonicFunction[RFAFact] {
    
    def apply(s: ISet[RFAFact], a: Assignment, currentNode: ICFGLocNode): ISet[RFAFact] = {
      val typ = ASTUtil.getType(a)
      var result = s
      val rhss = PilarAstHelper.getRHSs(a)
      ReachingFactsAnalysisHelper.updatePTAResultRHSs(rhss, typ, currentNode.getContext, s, ptaresult, apk)
      val lhss = PilarAstHelper.getLHSs(a)
      ReachingFactsAnalysisHelper.updatePTAResultLHSs(lhss, currentNode.getContext, s, ptaresult)
      val slotsWithMark = ReachingFactsAnalysisHelper.processLHSs(lhss, typ, currentNode.getContext, ptaresult, apk).values.flatten.toSet
      for (rdf @ RFAFact(_, _) <- s) {
        //if it is a strong definition, we can kill the existing definition
        if (slotsWithMark.contains(rdf.s, true)) {
          needtoremove += ((currentNode.getContext, rdf))
          result = result - rdf
        }
      }
      result
    }

    def apply(s: ISet[RFAFact], e: Exp, currentNode: ICFGLocNode): ISet[RFAFact] = {
      ReachingFactsAnalysisHelper.updatePTAResultExp(e, None, currentNode.getContext, s, ptaresult, apk) //FIXME double check the None here
      s
    }
    def apply(s: ISet[RFAFact], a: Action, currentNode: ICFGLocNode): ISet[RFAFact] = s
  }
  
  class Pstr extends PstProvider {
    def getPst(sig: Signature): ProcedureSymbolTable = {
      apk.getMethod(sig).get.getBody
    }
  }
  
  class Callr extends CallResolver[RFAFact] {
    val pureNormalFlagMap: MMap[ICFGNode, Boolean] = mmapEmpty
    /**
     * It returns the facts for each callee entry node and caller return node
     */
    def resolveCall(s: ISet[RFAFact], cj: CallJump, callerNode: ICFGNode, icfg: InterproceduralControlFlowGraph[ICFGNode]): (IMap[ICFGNode, ISet[RFAFact]], ISet[RFAFact]) = {
      val callerContext = callerNode.getContext
      ReachingFactsAnalysisHelper.updatePTAResultCallJump(cj, callerContext, s, ptaresult)
      val sig = ASTUtil.getSignature(cj).get
      val calleeSet = ReachingFactsAnalysisHelper.getCalleeSet(apk, cj, sig, callerContext, ptaresult)
      val icfgCallnode = icfg.getICFGCallNode(callerContext)
      icfgCallnode.asInstanceOf[ICFGCallNode].setCalleeSet(calleeSet)
      val icfgReturnnode = icfg.getICFGReturnNode(callerContext)
      icfgReturnnode.asInstanceOf[ICFGReturnNode].setCalleeSet(calleeSet)
      var calleeFactsMap: IMap[ICFGNode, ISet[RFAFact]] = imapEmpty
      var returnFacts: ISet[RFAFact] = s
      val genSet: MSet[RFAFact] = msetEmpty
      val killSet: MSet[RFAFact] = msetEmpty
      var pureNormalFlag = pureNormalFlagMap.getOrElseUpdate(callerNode, true)
      
      val args = cj.callExp.arg match{
        case te: TupleExp =>
          te.exps.map {
            case ne: NameExp => ne.name.name
            case exp => exp.toString
          }.toList
        case _ => throw new RuntimeException("wrong exp type: " + cj.callExp.arg)
      }
      calleeSet.foreach{
        callee =>
          val calleeSig = callee.callee
          icfg.getCallGraph.addCall(callerNode.getOwner, calleeSig)
          val calleep = apk.getMethod(calleeSig).get
          if(AndroidReachingFactsAnalysisHelper.isICCCall(calleeSig) || AndroidReachingFactsAnalysisHelper.isRPCCall(apk, currentComponent.getType, calleeSig) || AndroidReachingFactsAnalysisHelper.isModelCall(calleep)) {
            pureNormalFlag = false
            if(AndroidReachingFactsAnalysisHelper.isICCCall(calleeSig)) {
              // don't do anything for the ICC call now.
            } else if (AndroidReachingFactsAnalysisHelper.isRPCCall(apk, currentComponent.getType, calleeSig)) {
              // don't do anything for the RPC call now.
            } else { // for non-ICC-RPC model call
              val (g, k) = AndroidReachingFactsAnalysisHelper.doModelCall(ptaresult, calleep, args, cj.lhss.map(lhs=>lhs.name.name), callerContext, apk)
              genSet ++= g
              killSet ++= k
            }
          } else { // for normal call
            require(calleep.isConcrete)
            if(!icfg.isProcessed(calleeSig, callerContext)){
              icfg.collectCfgToBaseGraph[String](calleep, callerContext, isFirst = false)
              icfg.extendGraph(calleeSig, callerContext)
            }
            val factsForCallee = getFactsForCallee(s, cj, calleep, callerContext)
            killSet ++= factsForCallee
            calleeFactsMap += (icfg.entryNode(calleeSig, callerContext) -> mapFactsToCallee(factsForCallee, callerContext, cj, calleep))
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
      calleeFactsMap foreach {
        case (n, facts) =>
          facts foreach {
            f =>
              if(!f.s.isInstanceOf[StaticFieldSlot])
                ptaresult.addInstance(f.s, n.getContext, f.v)
          }
      }
      val lhss = PilarAstHelper.getLHSs(cj)
      val slotsWithMark = ReachingFactsAnalysisHelper.processLHSs(lhss, None, callerContext, ptaresult, apk).values.flatten.toSet
      for (rdf <- s) {
        //if it is a strong definition, we can kill the existing definition
        if (slotsWithMark.contains(rdf.s, true)) {
          killSet += rdf
        }
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
    
    private def getFactsForICCTarget(s: ISet[RFAFact], cj: CallJump, callerContext: Context): ISet[RFAFact] = {
      var calleeFacts = isetEmpty[RFAFact]
      calleeFacts ++= ReachingFactsAnalysisHelper.getGlobalFacts(s)
      cj.callExp.arg match{
        case te: TupleExp => 
          val exp = te.exps(1) //assume intent always the first arg
          exp match {
            case exp1: NameExp =>
              val slot = VarSlot(exp1.name.name, isBase = false, isArg = true)
              val value = ptaresult.pointsToSet(slot, callerContext)
              val instnums = value.map(factory.getInstanceNum)
              calleeFacts ++= value.map { r => new RFAFact(VarSlot(slot.varName, isBase = false, isArg = false), r) }
              calleeFacts ++= ReachingFactsAnalysisHelper.getRelatedHeapFacts(instnums, s)
            case _ =>
          }
          calleeFacts
        case _ => throw new RuntimeException("wrong exp type: " + cj.callExp.arg)
      }
    }
    
    private def getFactsForCallee(s: ISet[RFAFact], cj: CallJump, callee: JawaMethod, callerContext: Context): ISet[RFAFact] = {
      var calleeFacts = isetEmpty[RFAFact]
      val typ = ASTUtil.getKind(cj)
      
      calleeFacts ++= ReachingFactsAnalysisHelper.getGlobalFacts(s)
      cj.callExp.arg match{
        case te: TupleExp => 
          for(i <- te.exps.indices){
            val exp = te.exps(i)
            exp match {
              case exp1: NameExp =>
                val slot = VarSlot(exp1.name.name, isBase = false, isArg = true)
                var value = ptaresult.pointsToSet(slot, callerContext)
                if (typ != "static" && i == 0) {
                  value =
                    value.filter {
                      r =>
                        !r.isNull && !r.isUnknown && shouldPass(r, callee, typ)
                    }
                }
                calleeFacts ++= value.map { r => new RFAFact(VarSlot(slot.varName, isBase = false, isArg = false), r) }
                val instnums = value.map(factory.getInstanceNum)
                calleeFacts ++= ReachingFactsAnalysisHelper.getRelatedHeapFacts(instnums, s)
              case _ =>
            }
          }
          calleeFacts
        case _ => throw new RuntimeException("wrong exp type: " + cj.callExp.arg)
      }
    }
    
    /**
     * return true if the given recv Instance should pass to the given callee
     */
    private def shouldPass(recvIns: Instance, calleeProc: JawaMethod, typ: String): Boolean = {
      val recRecv = apk.getClassOrResolve(recvIns.typ)
      val recCallee = calleeProc.getDeclaringClass
      var tmpRec = recRecv
      if(typ == "direct" || typ == "super" ){
        true
      } else {
        while(tmpRec.hasSuperClass){
          if(tmpRec == recCallee) return true
          else if(tmpRec.declaresMethod(calleeProc.getSubSignature)) return false
          else tmpRec = apk.getClassOrResolve(tmpRec.getSuperClass)
        }
        if(tmpRec == recCallee) true
        else {
          apk.reporter.echo(TITLE, "Given recvIns: " + recvIns + " and calleeProc: " + calleeProc + " is not in the Same hierarchy.")
          false
        }
      }
    }
    
    def mapFactsToCallee(factsToCallee: ISet[RFAFact], callerContext: Context, cj: CallJump, calleep: JawaMethod): ISet[RFAFact] = {
      val varFacts = factsToCallee.filter(f=>f.s.isInstanceOf[VarSlot])
      val calleeMethod = calleep.getBody.procedure
      cj.callExp.arg match{
        case te: TupleExp =>
          val argSlots = te.exps.map {
            case ne: NameExp => VarSlot(ne.name.name, isBase = false, isArg = true)
            case exp => VarSlot(exp.toString, isBase = false, isArg = true)
          }
          val paramSlots: MList[VarSlot] = mlistEmpty
          calleeMethod.params.foreach{
            param =>
              require(param.typeSpec.isDefined)
              paramSlots += VarSlot(param.name.name, isBase = false, isArg = false)
          }
          var result = isetEmpty[RFAFact]
          
          for(i <- argSlots.indices){
            if(!paramSlots.isDefinedAt(i)){
              apk.reporter.error(TITLE, "argSlots does not adjust to paramSlots:\n" + callerContext + "\n" + argSlots + "\n" + calleep.getSignature + "\n" + paramSlots)
            } else {
              val argSlot = argSlots(i)
              val paramSlot = paramSlots(i)
              varFacts.foreach{
                fact =>
                  if(fact.s.getId == argSlot.getId) result += new RFAFact(paramSlot, fact.v)
              }
            }
          }
          factsToCallee -- varFacts ++ result
        case _ => throw new RuntimeException("wrong exp type: " + cj.callExp.arg)
      }
    }
    
    def mapFactsToICCTarget(factsToCallee: ISet[RFAFact], cj: CallJump, calleeMethod: ProcedureDecl): ISet[RFAFact] = {
      val varFacts = factsToCallee.filter(f=>f.s.isInstanceOf[VarSlot]).map{f=> RFAFact(f.slot, f.ins)}
      cj.callExp.arg match{
        case te: TupleExp =>
          val argSlot = te.exps(1) match{
            case ne: NameExp => VarSlot(ne.name.name, isBase = false, isArg = true)
            case exp => VarSlot(exp.toString, isBase = false, isArg = true)
          }
          val paramSlots: MList[VarSlot] = mlistEmpty
          calleeMethod.params.foreach{
            param =>
              require(param.typeSpec.isDefined)
              paramSlots += VarSlot(param.name.name, isBase = false, isArg = false)
          }
          var result = isetEmpty[RFAFact]
          val paramSlot = paramSlots.head
          varFacts.foreach{
            fact =>
              if(fact.s.getId == argSlot.getId) result += new RFAFact(paramSlot, fact.v)
          }
          factsToCallee -- varFacts ++ result
        case _ => throw new RuntimeException("wrong exp type: " + cj.callExp.arg)
      }
    }
    
    private def isReturnJump(loc: LocationDecl): Boolean = {
      loc.isInstanceOf[JumpLocation] && loc.asInstanceOf[JumpLocation].jump.isInstanceOf[ReturnJump]
    }
    
    def getAndMapFactsForCaller(calleeS: ISet[RFAFact], callerNode: ICFGNode, calleeExitNode: ICFGVirtualNode): ISet[RFAFact] ={
      val result = msetEmpty[RFAFact]
      val kill = msetEmpty[RFAFact]
      /**
       * adding global facts to result
       */
      result ++= ReachingFactsAnalysisHelper.getGlobalFacts(calleeS)
      
      val calleeMethod = apk.getMethod(calleeExitNode.getOwner).get.getBody.procedure
      val paramSlots: MList[VarSlot] = mlistEmpty
      calleeMethod.params.foreach{
        param =>
          paramSlots += VarSlot(param.name.name, isBase = false, isArg = false)
      }
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
          val cj = apk.getMethod(crn.getOwner).get.getBody.location(crn.getLocIndex).asInstanceOf[JumpLocation].jump.asInstanceOf[CallJump]
          val lhsSlots: ISeq[VarSlot] = cj.lhss.map{lhs=>VarSlot(lhs.name.name, isBase = false, isArg = false)}
          val retSlots: MSet[MList[VarSlot]] = msetEmpty
          calleeMethod.body match {
            case ib: ImplementedBody =>
              ib.locations.foreach {
                loc=>
                  if(isReturnJump(loc)){
                    val rj = loc.asInstanceOf[JumpLocation].jump.asInstanceOf[ReturnJump]
                    rj.exp match{
                      case Some(n) => 
                        n match{
                          case te: TupleExp => 
                            val tmplist: MList[VarSlot] = mlistEmpty
                            te.exps.foreach {
                              case ne: NameExp =>
                                tmplist += VarSlot(ne.name.name, isBase = false, isArg = false)
                              case _ =>
                            }
                            retSlots += tmplist
                          case _ => 
                        }
                      case None =>
                    }
                  }
              }
            case _ =>
          }
          cj.callExp.arg match{
            case te: TupleExp => 
              val argSlots = te.exps.map {
                case ne: NameExp => VarSlot(ne.name.name, isBase = false, isArg = true)
                case exp => VarSlot(exp.toString, isBase = false, isArg = true)
              }
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
            case _ => throw new RuntimeException("wrong exp type: " + cj.callExp.arg)
          }
          // kill the strong update for caller return node
          val lhss = PilarAstHelper.getLHSs(cj)
          val slotsWithMark = ReachingFactsAnalysisHelper.processLHSs(lhss, None, callerNode.getContext, ptaresult, apk).values.flatten.toSet
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
          lhsSlots.foreach {
            lhsSlot =>
              var values: ISet[Instance] = isetEmpty
              retSlots.foreach {
                retSlotList =>
                  calleeVarFacts.foreach{
                    case (s, v) =>
                      if(s == retSlotList(lhsSlots.indexOf(lhsSlot))){
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

  class NodeL extends NodeListener{
    def onPreVisitNode(node: ICFGNode, preds: CSet[ICFGNode]): Unit = {
      val bitset = if(preds.nonEmpty)preds.map{_.getLoadedClassBitSet}.reduce{ (x, y) => x.intersect(y)} else BitSet.empty
      node.setLoadedClassBitSet(bitset)
    }
    
    def onPostVisitNode(node: ICFGNode, succs: CSet[ICFGNode]): Unit = {
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
  final val ICC_EDGE = "icc"
  type Result = InterproceduralMonotoneDataFlowAnalysisResult[RFAFact]
  def apply(
      apk: ApkGlobal,
      entryPointProc: JawaMethod,
      initialFacts: ISet[RFAFact] = isetEmpty,
      clm: ClassLoadManager,
      initContext: Context,
      switchAsOrderedMatch: Boolean = false,
      timeout: Option[MyTimeout])(implicit factory: RFAFactFactory): InterproceduralDataFlowGraph
    = new AndroidReachingFactsAnalysisBuilder(apk, clm, timeout).build(entryPointProc, initialFacts, initContext, switchAsOrderedMatch)
}
