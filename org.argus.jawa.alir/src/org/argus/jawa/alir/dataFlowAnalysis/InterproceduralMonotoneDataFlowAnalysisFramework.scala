/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.dataFlowAnalysis

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.controlFlowGraph._
import org.argus.jawa.core.Signature
import org.sireum.alir._
import org.sireum.pilar.ast._
import org.sireum.pilar.symbol.ProcedureSymbolTable
import org.sireum.util._

import scala.collection.mutable
import scala.util.control.Breaks._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
trait InterproceduralMonotoneDataFlowAnalysisResult[LatticeElement] extends InterproceduralDataFlowAnalysisResult[LatticeElement] {
  def entrySet: ICFGNode => ISet[LatticeElement]
  def exitSet: ICFGNode => ISet[LatticeElement]
  def entries(n: ICFGNode, callerContext: Context, esl: EntrySetListener[LatticeElement])
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
trait InterProceduralMonotonicFunction[LatticeElement] {
  import org.sireum.pilar.ast._

  def apply(s: ISet[LatticeElement], a: Assignment, currentNode: ICFGLocNode): ISet[LatticeElement]
  def apply(s: ISet[LatticeElement], e: Exp, currentNode: ICFGLocNode): ISet[LatticeElement]
  def apply(s: ISet[LatticeElement], a: Action, currentNode: ICFGLocNode): ISet[LatticeElement]
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
trait NodeListener {
  def onPreVisitNode(node: InterproceduralMonotoneDataFlowAnalysisFramework.N, preds: CSet[InterproceduralMonotoneDataFlowAnalysisFramework.N])
  def onPostVisitNode(node: InterproceduralMonotoneDataFlowAnalysisFramework.N, succs: CSet[InterproceduralMonotoneDataFlowAnalysisFramework.N])
}

trait PstProvider {
  def getPst(sig: Signature): ProcedureSymbolTable
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
trait CallResolver[LatticeElement] {
  /**
   * It returns the facts for each callee entry node and caller return node
   */
  def resolveCall(s: ISet[LatticeElement], cj: CallJump, callerNode: ICFGNode, icfg: InterproceduralControlFlowGraph[ICFGNode]): (IMap[ICFGNode, ISet[LatticeElement]], ISet[LatticeElement])
  def getAndMapFactsForCaller(calleeS: ISet[LatticeElement], callerNode: ICFGNode, calleeExitNode: ICFGVirtualNode): ISet[LatticeElement]
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
object InterproceduralMonotoneDataFlowAnalysisFramework {
  
  final val TITLE = "InterProceduralMonotoneDataFlowAnalysisFramework"
  type N = ICFGNode
  def apply[LatticeElement] = build0[LatticeElement] _

  def build0[LatticeElement] //
  (icfg: InterproceduralControlFlowGraph[N],
   forward: Boolean, lub: Boolean, rapid: Boolean, par: Boolean,
   gen: InterProceduralMonotonicFunction[LatticeElement],
   kill: InterProceduralMonotonicFunction[LatticeElement],
   callr: CallResolver[LatticeElement],
   ppr: PstProvider,
   iota: ISet[LatticeElement],
   initial: ISet[LatticeElement],
   switchAsOrderedMatch: Boolean = false,
   nl: Option[NodeListener] = None): //
   InterproceduralMonotoneDataFlowAnalysisResult[LatticeElement] = {
    val flow = if (forward) icfg else icfg.reverse
    val startNode = flow.entryNode
    build(icfg, forward, lub, rapid, par, gen, kill, callr, ppr, startNode, iota, initial, switchAsOrderedMatch, nl)
  }
  
  def build[LatticeElement] //
  (icfg: InterproceduralControlFlowGraph[N],
   forward: Boolean, lub: Boolean, rapid: Boolean, par: Boolean,
   gen: InterProceduralMonotonicFunction[LatticeElement],
   kill: InterProceduralMonotonicFunction[LatticeElement],
   callr: CallResolver[LatticeElement],
   ppr: PstProvider,
   startNode: N,
   iota: ISet[LatticeElement],
   initial: ISet[LatticeElement],
   switchAsOrderedMatch: Boolean = false,
   nl: Option[NodeListener] = None): //
   InterproceduralMonotoneDataFlowAnalysisResult[LatticeElement] = {

    val confluence = if (lub) iunion[LatticeElement] _ else iintersect[LatticeElement] _
    val bigConfluence: Iterable[ISet[LatticeElement]] => ISet[LatticeElement] =
      if (lub) bigIUnion else bigIIntersect
      
    val entrySetMap = if(par) new mutable.HashMap[N, ISet[LatticeElement]] with mutable.SynchronizedMap[N, ISet[LatticeElement]]
                      else new mutable.HashMap[N, ISet[LatticeElement]]
    
    def getEntrySet(n: N) = entrySetMap.getOrElse(n, initial)
    
    class IMdaf(val entrySet: N => ISet[LatticeElement],
               initial: ISet[LatticeElement])
        extends InterproceduralMonotoneDataFlowAnalysisResult[LatticeElement] {
      type DFF = ISet[LatticeElement]

      override def toString = {
        val sb = new StringBuilder
        var i = 1
        breakable{
          for (n <- icfg.nodes) {
            i += 1
            if(i < 1000){
              sb.append("%s = %s\n".format(n, entrySet(n).toString))
            } else break
          }
        }
        sb.append("\n")

        sb.toString
      }
      
      def exitSet: N => DFF = {
        case en: ICFGEntryNode =>
          getEntrySet(en)
        case xn: ICFGExitNode =>
          getEntrySet(xn)
        case cn: ICFGCallNode =>
          val r = caculateResult(cn)
          r.values.reduce(iunion[LatticeElement])
        case rn: ICFGReturnNode =>
          getEntrySet(rn)
        case nn: ICFGNormalNode =>
          val r = caculateResult(nn)
          r.values.reduce(iunion[LatticeElement])
        case a => throw new RuntimeException("unexpected node type: " + a)
      }

      
      protected def next(l: LocationDecl, pst: ProcedureSymbolTable, pSig: Signature, callerContext: Context) = {
        val newLoc = pst.location(l.index + 1)
        val newContext = callerContext.copy
        if(newLoc.name.isEmpty)
          newContext.setContext(pSig, newLoc.index.toString)
        else 
          newContext.setContext(pSig, newLoc.name.get.uri)
        if(icfg.isCall(newLoc))
          icfg.getICFGCallNode(newContext)
        else
          icfg.getICFGNormalNode(newContext)
      }

      protected def node(l: LocationDecl, context: Context) = {
        if(icfg.isCall(l))
          icfg.getICFGCallNode(context)
        else
          icfg.getICFGNormalNode(context)
      }

      protected def fA(a: Assignment, in: DFF, currentNode: ICFGLocNode): DFF =
        kill(in, a, currentNode).union(gen(in, a, currentNode))
        
      protected def fC(a: Action, in: DFF, currentNode: ICFGLocNode): DFF =
        kill(in, a, currentNode).union(gen(in, a, currentNode))

      protected def fE(e: Exp, in: DFF, currentNode: ICFGLocNode): DFF =
        kill(in, e, currentNode).union(gen(in, e, currentNode))

      protected def fOE(eOpt: Option[Exp], in: DFF, currentNode: ICFGLocNode): DFF =
        if (eOpt.isDefined) fE(eOpt.get, in, currentNode) else in

      protected def actionF(in: DFF, a: Action, currentNode: ICFGLocNode) =
        a match {
          case a: AssignAction => fA(a, in, currentNode)
          case a: AssertAction => fC(a, in, currentNode)
          case a: AssumeAction => fC(a, in, currentNode)
          case a: ThrowAction  => fC(a, in, currentNode)
          case a: StartAction =>
            if (forward)
              fOE(a.arg, fOE(a.count, in, currentNode), currentNode)
            else
              fOE(a.count, fOE(a.arg, in, currentNode), currentNode)
          case a: ExtCallAction => fA(a, in, currentNode)
        }
      
      def update(s: DFF, n: N): Boolean = {
        val oldS = getEntrySet(n)
        val newS = s
        if (oldS != newS) {
          entrySetMap.update(n, newS)
          true
        } else
          false
      }

      protected def visitBackward(
        currentNode: ICFGLocNode,
        esl: Option[EntrySetListener[LatticeElement]]): IMap[N, DFF] = {
        val pSig = currentNode.getOwner
        val pst = ppr.getPst(pSig)
        val l = pst.location(currentNode.getLocIndex)
        val currentContext = currentNode.getContext
        val callerContext = currentContext.copy.removeTopContext()
        
        val latticeMap: MMap[N, DFF] = mmapEmpty
        
        if(l.name.isEmpty)
          currentContext.setContext(pSig, l.index.toString)
        else
          currentContext.setContext(pSig, l.name.get.uri)
        val eslb = esl.orNull
          def jumpF(j: Jump): DFF =
            j match {
              case j: IfJump =>
                var result = initial
                val numOfIfThens = j.ifThens.size
                for (i <- 0 until numOfIfThens) {
                  val ifThen = j.ifThens(i)
                  val ifThenContext = callerContext.copy
                  ifThenContext.setContext(pSig, ifThen.target.uri)
                  val ifThenLoc = pst.location(ifThen.target.uri)
                  val sn = node(ifThenLoc, ifThenContext)
                  var r = getEntrySet(sn)
                  for (k <- tozero(i)) {
                    val it = j.ifThens(k)
                    r = fE(it.cond, r, currentNode)
                  }
                  result = confluence(result, r)
                }
                {
                  val ifElse = j.ifElse
                  val ifElseDefined = ifElse.isDefined
                  val sn =
                    if (ifElseDefined) {
                      val ifElseContext = callerContext.copy
                      ifElseContext.setContext(pSig, ifElse.get.target.uri)
                      val ifElseLoc = pst.location(ifElse.get.target.uri)
                      node(ifElseLoc, ifElseContext)
                    }
                    else next(l, pst, pSig, callerContext)
                  var r = getEntrySet(sn)
                  for (k <- tozero(numOfIfThens - 1)) {
                    val it = j.ifThens(k)
                    r = fE(it.cond, r, currentNode)
                  }
                  if (ifElseDefined && esl.isDefined) eslb.ifElse(ifElse.get, r)
                  result = confluence(result, r)
                }
                if (esl.isDefined) eslb.ifJump(j, result)
                result
              case j: SwitchJump =>
                var result = initial
                val numOfCases = j.cases.size
                for (i <- 0 until numOfCases) {
                  val switchCase = j.cases(i)
                  val switchCaseContext = callerContext.copy
                  switchCaseContext.setContext(pSig, switchCase.target.uri)
                  val switchCaseLoc = pst.location(switchCase.target.uri)
                  val sn = node(switchCaseLoc, switchCaseContext)
                  var r = getEntrySet(sn)
                  if (switchAsOrderedMatch)
                    for (k <- tozero(i)) {
                      val sc = j.cases(k)
                      r = fE(sc.cond, r, currentNode)
                    }
                  else
                    r = fE(switchCase.cond, r, currentNode)
                  if (esl.isDefined) eslb.switchCase(switchCase, r)
                  result = confluence(result, r)
                }
                {
                  val switchDefault = j.defaultCase
                  val switchDefaultDefined = switchDefault.isDefined
                  val sn =
                    if (switchDefaultDefined){
                      val switchDefaultContext = callerContext.copy
                      switchDefaultContext.setContext(pSig, switchDefault.get.target.uri)
                      val switchDefaultLoc = pst.location(switchDefault.get.target.uri)
                      node(switchDefaultLoc, switchDefaultContext)
                    }
                    else next(l, pst, pSig, callerContext)
                  var r = getEntrySet(sn)
                  if (switchAsOrderedMatch)
                    for (k <- tozero(numOfCases - 1)) {
                      val sc = j.cases(k)
                      r = fE(sc.cond, r, currentNode)
                    }
                  if (esl.isDefined && switchDefaultDefined)
                    eslb.switchDefault(switchDefault.get, r)
                  result = confluence(result, r)
                }
                if (esl.isDefined)
                  eslb.switchJump(j, result)
                result
              case j: GotoJump =>
                val jContext = callerContext.copy
                jContext.setContext(pSig, j.target.uri)
                val jLoc = pst.location(j.target.uri)
                val sn = node(jLoc, jContext)
                val result = getEntrySet(sn)
                if (esl.isDefined)
                  eslb.gotoJump(j, result)
                result
              case j: ReturnJump =>
                val exitContext = callerContext.copy
                exitContext.setContext(pSig, pSig.signature)
                val sn = icfg.getICFGExitNode(exitContext)
                val result = fOE(j.exp, getEntrySet(sn), currentNode)
                if (esl.isDefined)
                  eslb.returnJump(j, result)
                result
              case j: CallJump =>
                val s =
                  if (j.jump.isEmpty)
                    getEntrySet(next(l, pst, pSig, callerContext))
                  else
                    jumpF(j.jump.get)
                val result = fA(j, s, currentNode)
                if (esl.isDefined)
                  eslb.callJump(j, result)
                result
            }
        val ln = node(l, currentContext)
        l match {
          case l: ComplexLocation =>
            val result = bigConfluence(l.transformations.map { t =>
              var r =
                if (t.jump.isEmpty)
                  getEntrySet(next(l, pst, pSig, callerContext))
                else
                  jumpF(t.jump.get)
              val numOfActions = t.actions.size
              for (i <- untilzero(numOfActions)) {
                val a = t.actions(i)
                r = actionF(r, a, currentNode)
                if (esl.isDefined) eslb.action(a, r)
              }
              if (esl.isDefined) eslb.exitSet(None, r)
              r
            })
            latticeMap += (ln -> result)
          case l: ActionLocation =>
            val result = actionF(getEntrySet(next(l, pst, pSig, callerContext)), l.action, currentNode)
            if (esl.isDefined) {
              eslb.action(l.action, result)
              eslb.exitSet(None, result)
            }
            latticeMap += (ln -> result)
          case l: JumpLocation =>
            val result = jumpF(l.jump)
            if (esl.isDefined) {
              eslb.exitSet(None, result)
            }
            latticeMap += (ln -> result)
          case l: EmptyLocation =>
            val result = getEntrySet(next(l, pst, pSig, callerContext))
            if (esl.isDefined) {
              eslb.exitSet(None, result)
            }
            latticeMap += (ln -> result)
        }
        latticeMap.toMap
      }
      

      protected def visitForward(
        currentNode: ICFGLocNode,
        esl: Option[EntrySetListener[LatticeElement]]): IMap[N, DFF] = {
        val pSig = currentNode.getOwner
        val pst = ppr.getPst(pSig)
        val l = pst.location(currentNode.getLocIndex)
        val currentContext = currentNode.getContext
        val callerContext = currentContext.copy.removeTopContext()

        val latticeMap: MMap[N, DFF] = mmapEmpty

        val eslb = esl.orNull
        def jumpF(s: DFF, j: Jump): Unit =
          j match {
            case j: IfJump =>
              var r = s
              if (esl.isDefined) eslb.ifJump(j, s)
              for (ifThen <- j.ifThens) {
                r = fE(ifThen.cond, r, currentNode)
                val ifThenContext = callerContext.copy
                ifThenContext.setContext(pSig, ifThen.target.uri)
                val ifThenLoc = pst.location(ifThen.target.uri)
                val sn = node(ifThenLoc, ifThenContext)
                if (esl.isDefined) {
                  eslb.ifThen(ifThen, r)
                  eslb.exitSet(Some(ifThen), r)
                }
                latticeMap += (sn -> r)
              }
              if (j.ifElse.isEmpty) {
                val sn = next(l, pst, pSig, callerContext)
                if (esl.isDefined) eslb.exitSet(None, r)
                latticeMap += (sn -> r)
              } else {
                val ifElse = j.ifElse.get
                val ifElseContext = callerContext.copy
                ifElseContext.setContext(pSig, ifElse.target.uri)
                val ifElseLoc = pst.location(ifElse.target.uri)
                val sn = node(ifElseLoc, ifElseContext)
                if (esl.isDefined) {
                  eslb.ifElse(ifElse, r)
                  eslb.exitSet(Some(ifElse), r)
                }
                latticeMap += (sn -> r)
              }
            case j: SwitchJump =>
              var r = s
              if (esl.isDefined) eslb.switchJump(j, s)
              for (switchCase <- j.cases) {
                r =
                  if (switchAsOrderedMatch)
                    fE(switchCase.cond, r, currentNode)
                  else
                    fE(switchCase.cond, s, currentNode)
                val switchCaseContext = callerContext.copy
                switchCaseContext.setContext(pSig, switchCase.target.uri)
                val switchCaseLoc = pst.location(switchCase.target.uri)
                val sn = node(switchCaseLoc, switchCaseContext)
                if (esl.isDefined) {
                  eslb.switchCase(switchCase, r)
                  eslb.exitSet(Some(switchCase), r)
                }
                latticeMap += (sn -> r)
              }
              if (j.defaultCase.isEmpty) {
                val sn = next(l,pst, pSig, callerContext)
                if (esl.isDefined) eslb.exitSet(None, r)
                latticeMap += (sn -> r)
              } else {
                val switchDefault = j.defaultCase.get
                val switchDefaultContext = callerContext.copy
                switchDefaultContext.setContext(pSig, switchDefault.target.uri)
                val switchDefaultLoc = pst.location(switchDefault.target.uri)
                val sn = node(switchDefaultLoc, switchDefaultContext)
                if (esl.isDefined) {
                  eslb.switchDefault(switchDefault, r)
                  eslb.exitSet(Some(switchDefault), r)
                }
                latticeMap += (sn -> r)
              }
            case j: GotoJump =>
              val gotoContext = callerContext.copy
              gotoContext.setContext(pSig, j.target.uri)
              val gotoLoc = pst.location(j.target.uri)
              val sn = node(gotoLoc, gotoContext)
              if (esl.isDefined) {
                eslb.gotoJump(j, s)
                eslb.exitSet(Some(j), s)
              }
              latticeMap += (sn -> s)
            case j: ReturnJump =>
              val exitContext = callerContext.copy
              exitContext.setContext(pSig, "Exit")
              val sn = icfg.getICFGExitNode(exitContext)
              val r = fOE(j.exp, s, currentNode)
              if (esl.isDefined) {
                eslb.returnJump(j, r)
                eslb.exitSet(Some(j), r)
              }
              latticeMap += (sn -> r)
            case j: CallJump =>
              if (esl.isDefined) eslb.callJump(j, s)
//              val r = fA(j, s, currentNode)
              if (j.jump.isEmpty) {
                val (calleeFactsMap, retFacts) = callr.resolveCall(s, j, currentNode, icfg)
                calleeFactsMap.foreach{
                  case (calleeNode, calleeFacts) =>
                    latticeMap += (calleeNode -> calleeFacts)
                }
                val rn = icfg.getICFGReturnNode(currentContext)
                latticeMap += (rn -> retFacts)
                if (esl.isDefined) eslb.exitSet(None, getEntrySet(rn))
              } else
                jumpF(s, j.jump.get)
        }
        
        val s = getEntrySet(currentNode)
        l match {
          case l: ComplexLocation =>
            l.transformations.foreach { t =>
              var r = s
              t.actions.foreach { a =>
                if (esl.isDefined) eslb.action(a, r)
                r = actionF(r, a, currentNode)
              }
              if (t.jump.isDefined)
                jumpF(r, t.jump.get)
              else {
                val sn = next(l, pst, pSig, callerContext)
                if (esl.isDefined) eslb.exitSet(None, r)
                latticeMap += (sn -> r)
              }
            }
          case l: ActionLocation =>
            if(esl.isDefined) eslb.action(l.action, s)
            val r = actionF(s, l.action, currentNode)
            if(esl.isDefined) eslb.exitSet(None, r)
            val node = icfg.getICFGNormalNode(currentContext)
            val succs = icfg.successors(node)
            succs.foreach(succ=>latticeMap += (succ -> r))
          case l: JumpLocation =>
            jumpF(s, l.jump)
          case l: EmptyLocation =>
            if (esl.isDefined)
              eslb.exitSet(None, s)
            val sn = next(l, pst, pSig, callerContext)
            latticeMap += (sn -> s)
        }
        latticeMap.toMap
      }
      
      def caculateResult(currentNode: ICFGLocNode,
                esl: Option[EntrySetListener[LatticeElement]] = None): IMap[N, DFF] = {
        if (forward) visitForward(currentNode, esl)
        else visitBackward(currentNode, esl)
      }

      def visit(currentNode: ICFGLocNode,
                esl: Option[EntrySetListener[LatticeElement]] = None): Boolean = {
        caculateResult(currentNode, esl).map{case (n, facts) => 
//          println(confluence(facts, getEntrySet(n)))
          update(confluence(facts, getEntrySet(n)), n)}.exists(_ == true)
      }

      
      def entries(n: N, callerContext: Context, esl: EntrySetListener[LatticeElement]) = {
        n match {
          case cn: ICFGLocNode  =>
            visit(cn, Some(esl))
          case _ =>
        }
      }

    }
    
    val imdaf = new IMdaf(getEntrySet _, initial)
    
    def process(n: N): ISet[N] = {
      var result = isetEmpty[N]
      n match {
        case en: ICFGEntryNode =>
          for (succ <- icfg.successors(n)) {
            if(imdaf.update(getEntrySet(en), succ)){
              result += succ
            }
          }
        case xn: ICFGExitNode =>
          for (succ <- icfg.successors(n)){
            val factsForCaller = callr.getAndMapFactsForCaller(getEntrySet(xn), succ, xn)
            imdaf.update(confluence(getEntrySet(succ), factsForCaller), succ)
            result += succ
          }
        case cn: ICFGCallNode =>
          if (imdaf.visit(cn)){
            result ++= icfg.successors(n)
          }
        case rn: ICFGReturnNode =>
          for (succ <- icfg.successors(n)) {
            if(imdaf.update(getEntrySet(n), succ)){
              result += succ
            }
          }
        case nn: ICFGNormalNode =>
          if (imdaf.visit(nn)){
            result ++= icfg.successors(n)
          }
        case a => throw new RuntimeException("unexpected node type: " + a)
      }
      result
    }
    
    entrySetMap.put(startNode, iota)
    val workList = mlistEmpty[N]
    workList += startNode
    val ensurer = new ConvergeEnsurer
    while(workList.nonEmpty){
      while (workList.nonEmpty) {
        if(false){
          val newworkList = workList.map{
            n =>
              ensurer.updateNodeCount(n)
                if(nl.isDefined) nl.get.onPreVisitNode(n, icfg.predecessors(n))
                val newnodes = process(n)
                if(nl.isDefined) nl.get.onPostVisitNode(n, icfg.successors(n))
                newnodes
          }.reduce(iunion[N])
          workList.clear
          workList ++= newworkList.filter(ensurer.checkNode)
        } else {
          val n = workList.remove(0)
          if(ensurer.checkNode(n)) {
            ensurer.updateNodeCount(n)
            if(nl.isDefined) nl.get.onPreVisitNode(n, icfg.predecessors(n))
            val newWorks = process(n)
            workList ++= {newWorks -- workList}
            if(nl.isDefined) nl.get.onPostVisitNode(n, icfg.successors(n))
          }
        }
      }
      val nodes = if(false) icfg.nodes.par else icfg.nodes
      workList ++= nodes.map{
        node =>
          var newnodes = isetEmpty[N]
          node match{
            case xn: ICFGExitNode =>
              if(nl.isDefined) nl.get.onPreVisitNode(xn, icfg.predecessors(xn))
              val succs = icfg.successors(xn)
              for (succ <- succs){
                val factsForCaller = callr.getAndMapFactsForCaller(getEntrySet(xn), succ, xn)
                if(imdaf.update(confluence(getEntrySet(succ), factsForCaller), succ))
                  newnodes += succ
              }
              if(nl.isDefined) nl.get.onPostVisitNode(xn, succs)
            case _ =>
          }
          newnodes
      }.reduce(iunion[N])
    }
    imdaf
  }
  /**
   * Theoretically the algorithm should converge if it's implemented correctly, but just in case.
   */
  class ConvergeEnsurer {
    private val limit: Int = 200
    private val usagemap: MMap[N, Int] = mmapEmpty
    private val nonConvergeNodes: MSet[N] = msetEmpty
    def checkNode(n: N): Boolean = {
      val c = this.usagemap.getOrElseUpdate(n, 0)
      if(c >= limit){
        this.nonConvergeNodes += n
        false
      }
      else true
    }
    def updateNodeCount(n: N) = this.usagemap(n) = this.usagemap.getOrElseUpdate(n, 0) + 1
  }
}
