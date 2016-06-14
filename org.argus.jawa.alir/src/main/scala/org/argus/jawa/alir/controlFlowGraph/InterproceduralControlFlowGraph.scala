/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.controlFlowGraph

import org.argus.jawa.alir.callGraph.CallGraph
import org.argus.jawa.alir.{Context, JawaAlirInfoProvider}
import org.argus.jawa.alir.interprocedural.{Callee, InterproceduralGraph, InterproceduralNode}
import org.argus.jawa.core.util.ASTUtil
import org.argus.jawa.core.{Global, JawaMethod, Signature}
import org.sireum.alir._
import org.sireum.pilar.symbol.ProcedureSymbolTable
import org.sireum.util._
import org.sireum.pilar.ast._

import scala.collection.immutable.BitSet
import scala.collection.mutable

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class InterproceduralControlFlowGraph[Node <: ICFGNode] extends InterproceduralGraph[Node]{
  private var succBranchMap: MMap[(Node, Option[Branch]), Node] = null
  private var predBranchMap: MMap[(Node, Option[Branch]), Node] = null
  val BRANCH_PROPERTY_KEY = ControlFlowGraph.BRANCH_PROPERTY_KEY
  final val EDGE_TYPE = "EdgeType"
  
  def addEdge(source: Node, target: Node, typ: String): Edge = {
    val e = addEdge(source, target)
    if(typ != null)
      e.setProperty(EDGE_TYPE, typ)
    e
  }
  
  def isEdgeType(e: Edge, typ: String): Boolean = {
    e.getPropertyOrElse[String](EDGE_TYPE, null) == typ
  }
    
  protected var entryN: ICFGNode = null

  protected var exitN: ICFGNode = null
  
  def addEntryNode(en: ICFGEntryNode) = this.entryN = en
  def addExitNode(en: ICFGExitNode) = this.exitN = en
  
  def entryNode: Node = this.entryN.asInstanceOf[Node]
  
  def exitNode: Node = this.exitN.asInstanceOf[Node]
  
  private val cg: CallGraph = new CallGraph
  
  def getCallGraph: CallGraph = this.cg
  
  private val processed: MMap[(Signature, Context), ISet[Node]] = new mutable.HashMap[(Signature, Context), ISet[Node]] with mutable.SynchronizedMap[(Signature, Context), ISet[Node]]
  
  def isProcessed(proc: Signature, callerContext: Context): Boolean = processed.contains(proc, callerContext)
  
  def addProcessed(jp: Signature, c: Context, nodes: ISet[Node]) = {
    this.processed += ((jp, c) -> nodes)
  }
  
  def getProcessed = this.processed
  
  def entryNode(proc: Signature, callerContext: Context): Node = {
    require(isProcessed(proc, callerContext))
    processed(proc, callerContext).foreach{
      n => if(n.isInstanceOf[ICFGEntryNode]) return n
    }
    throw new RuntimeException("Cannot find entry node for: " + proc)
  }
  
  def reverse: InterproceduralControlFlowGraph[Node] = {
    val result = new InterproceduralControlFlowGraph[Node]
    for (n <- nodes) result.addNode(n)
    for (e <- edges) result.addEdge(e.target, e.source)
    result.entryN = this.exitNode
    result.exitN = this.entryNode
    result
  }
    
//  private def putBranchOnEdge(trans: Int, branch: Int, e: Edge) = {
//    e(BRANCH_PROPERTY_KEY) = (trans, branch)
//  }

  private def getBranch(pst: ProcedureSymbolTable, e: Edge): Option[Branch] = {
    if (e ? BRANCH_PROPERTY_KEY) {
      val p: (Int, Int) = e(BRANCH_PROPERTY_KEY)
      var j =
        PilarAstUtil.getJumps(pst.location(
          e.source.asInstanceOf[AlirLocationNode].locIndex))(first2(p)).get
      val i = second2(p)

      j match {
        case jump: CallJump => j = jump.jump.get
        case _ =>
      }

      (j: @unchecked) match {
        case gj: GotoJump   => Some(gj)
        case rj: ReturnJump => Some(rj)
        case ifj: IfJump =>
          if (i == 0) ifj.ifElse
          else Some(ifj.ifThens(i - 1))
        case sj: SwitchJump =>
          if (i == 0) sj.defaultCase
          else Some(sj.cases(i - 1))
      }
    } else None
  }

  def useBranch[T](pst: ProcedureSymbolTable)(f: => T): T = {
    succBranchMap = mmapEmpty
    predBranchMap = mmapEmpty
    for (node <- this.nodes) {
      for (succEdge <- successorEdges(node)) {
        val b = getBranch(pst, succEdge)
        val s = edgeSource(succEdge)
        val t = edgeTarget(succEdge)
        succBranchMap((node, b)) = t
        predBranchMap((t, b)) = s
      }
    }
    val result = f
    succBranchMap = null
    predBranchMap = null
    result
  }
    
    
    def successor(node: Node, branch: Option[Branch]): Node = {
      assert(succBranchMap != null,
        "The successor method needs useBranch as enclosing context")
      succBranchMap((node, branch))
    }

    def predecessor(node: Node, branch: Option[Branch]): Node = {
      assert(predBranchMap != null,
        "The successor method needs useBranch as enclosing context")
      predBranchMap((node, branch))
    }

    override def toString = {
      val sb = new StringBuilder("system CFG\n")

      for (n <- nodes)
        for (m <- successors(n)) {
          for (e <- getEdges(n, m)) {
            val branch = if (e ? BRANCH_PROPERTY_KEY)
              e(BRANCH_PROPERTY_KEY).toString
            else ""
              sb.append("%s -> %s %s\n".format(n, m, branch))
          }
        }

      sb.append("\n")

      sb.toString
    }
  
  /**
   * (We ASSUME that predecessors ???? and successors of n are within the same method as of n)
   * So, this algorithm is only for an internal node of a method NOT for a method's Entry node or Exit node
   * The algorithm is obvious from the following code 
   */
  def compressByDelNode (n: Node) = {
    val preds = predecessors(n) - n
    val succs = successors(n) - n
    deleteNode(n)
    for(pred <- preds){
      for(succ <- succs){           
        if (!hasEdge(pred,succ)){
          addEdge(pred, succ)
        }
      }
    }
  }
  
  // read the sCfg and build a corresponding DFA/NFA  
//  def buildAutomata(): Automaton = {
//    val automata = new Automaton()
//    // build a map between sCfg-nodes-set and automata-nodes-set
//    val nodeMap:MMap[Node, State] = mmapEmpty
//
//    nodes.foreach(
//      gNode => {
//        val state = new State()
//        state.setAccept(true)  // making each state in the automata an accept state
//        nodeMap(gNode) = state
//      }
//    )
//    // build a map between Entry-nodes-set (in sCfg) to English characters (assuming Entry-nodes-set is small); note that each call corresponds to an edge to Entry node of callee proc
//    val calleeMap:MMap[Node, Char] = mmapEmpty
//    var calleeIndex = 0
//    nodes.foreach(
//      gNode => {   // ******* below check the hard-coded path for testing ***********
//        if(!gNode.toString.contains("pilar:/method/default/%5B%7Cde::mobinauten") && gNode.toString.endsWith(".Entry"))
//        {
//          calleeMap(gNode) = ('A' + calleeIndex).toChar
//          println("in calleeMap: node " + gNode.toString + "  has label = " + calleeMap(gNode))
//          calleeIndex = calleeIndex + 1
//        }
//      }
//    )
//    // build the automata from the sCfg
//
//    nodes.foreach(
//      gNode => {
//        val automataNode = nodeMap(gNode)   // automataNode = automata state
//        val gSuccs = successors(gNode)
//        var label: Char = 'x'  // default label of automata transition
//        gSuccs.foreach(
//          gSucc => {
//            val automataSucc = nodeMap(gSucc)
//            if(calleeMap.contains(gSucc))
//              label = calleeMap(gSucc)
//            val tr = new Transition(label, automataSucc)
//            automataNode.addTransition(tr)
//          }
//        )
//      }
//    )
//   automata
//  }
   
  def isCall(l: LocationDecl): Boolean = l.isInstanceOf[JumpLocation] && l.asInstanceOf[JumpLocation].jump.isInstanceOf[CallJump]
   
  def merge(icfg: InterproceduralControlFlowGraph[Node]) = {
    this.pl ++= icfg.pool
    icfg.nodes.foreach(addNode(_))
    icfg.edges.foreach(addEdge(_))
    icfg.getCallGraph.getCallMap.foreach{
      case (src, dsts) =>
        cg.addCalls(src, cg.getCallMap.getOrElse(src, isetEmpty) ++ dsts)
    }
    this.processed ++= icfg.processed
    if(this.predBranchMap != null && icfg.predBranchMap != null)
      this.predBranchMap ++= icfg.predBranchMap
    if(this.succBranchMap != null && icfg.succBranchMap != null)
      this.succBranchMap ++= icfg.succBranchMap
  }
  
  def collectCfgToBaseGraph[VirtualLabel](calleeProc: JawaMethod, callerContext: Context, isFirst: Boolean = false): ISet[Node] = {
    this.synchronized{
      val calleeSig = calleeProc.getSignature
      val body = calleeProc.getBody
//      val rawcode = JawaCodeSource.getMethodCodeWithoutFailing(calleeProc.getSignature)
//      val codes = rawcode.split("\\r?\\n")
      val cfg = JawaAlirInfoProvider.getCfg(calleeProc)
      var nodes = isetEmpty[Node]
      cfg.nodes map {
        case vn@AlirVirtualNode(label) =>
          vn.label.toString match {
            case "Entry" =>
              val entryNode = addICFGEntryNode(callerContext.copy.setContext(calleeSig, "Entry"))
              entryNode.setOwner(calleeProc.getSignature)
              nodes += entryNode
              if (isFirst) this.entryN = entryNode
            case "Exit" =>
              val exitNode = addICFGExitNode(callerContext.copy.setContext(calleeSig, "Exit"))
              exitNode.setOwner(calleeProc.getSignature)
              nodes += exitNode
              if (isFirst) this.exitN = exitNode
            case a => throw new RuntimeException("unexpected virtual label: " + a)
          }
        case ln: AlirLocationUriNode =>
          val l = body.location(ln.locIndex)
          //              val code = codes.find(_.contains("#" + ln.locUri + ".")).getOrElse(throw new RuntimeException("Could not find " + ln.locUri + " from \n" + rawcode))
          if (isCall(l)) {
            val cj = l.asInstanceOf[JumpLocation].jump.asInstanceOf[CallJump]
            val sig = ASTUtil.getSignature(cj).get
            val callType = ASTUtil.getKind(cj)
            val argNames: MList[String] = mlistEmpty
            val retNames: MList[String] = mlistEmpty
            l match {
              case jumploc: JumpLocation =>
                argNames ++= ASTUtil.getCallArgs(jumploc)
                retNames ++= ASTUtil.getReturnVars(jumploc)
              case _ =>
            }
            val c = addICFGCallNode(callerContext.copy.setContext(calleeSig, ln.locUri))
            c.setOwner(calleeProc.getSignature)
            c.asInstanceOf[ICFGInvokeNode].argNames = argNames.toList
            c.asInstanceOf[ICFGInvokeNode].retNames = retNames.toList
            //                c.setCode(code)
            c.asInstanceOf[ICFGLocNode].setLocIndex(ln.locIndex)
            c.asInstanceOf[ICFGInvokeNode].setCalleeSig(sig)
            c.asInstanceOf[ICFGInvokeNode].setCallType(callType)
            nodes += c
            val r = addICFGReturnNode(callerContext.copy.setContext(calleeSig, ln.locUri))
            r.setOwner(calleeProc.getSignature)
            r.asInstanceOf[ICFGInvokeNode].argNames = argNames.toList
            r.asInstanceOf[ICFGInvokeNode].retNames = retNames.toList
            //                r.setCode(code)
            r.asInstanceOf[ICFGLocNode].setLocIndex(ln.locIndex)
            r.asInstanceOf[ICFGInvokeNode].setCalleeSig(sig)
            r.asInstanceOf[ICFGInvokeNode].setCallType(callType)
            nodes += r
            addEdge(c, r)
          } else {
            val node = addICFGNormalNode(callerContext.copy.setContext(calleeSig, ln.locUri))
            node.setOwner(calleeProc.getSignature)
            //                node.setCode(code)
            node.asInstanceOf[ICFGLocNode].setLocIndex(ln.locIndex)
            nodes += node
          }
        case a: AlirLocationNode =>
          // should not have a chance to reach here.
          val node = addICFGNormalNode(callerContext.copy.setContext(calleeSig, a.locIndex.toString))
          node.setOwner(calleeProc.getSignature)
          //              node.setCode("unknown")
          node.asInstanceOf[ICFGLocNode].setLocIndex(a.locIndex)
          nodes += node
      }
      for (e <- cfg.edges) {
        val entryNode = getICFGEntryNode(callerContext.copy.setContext(calleeSig, "Entry"))
        val exitNode = getICFGExitNode(callerContext.copy.setContext(calleeSig, "Exit"))
        e.source match{
          case AlirVirtualNode(label) =>
            e.target match{
              case AlirVirtualNode(`label`) =>
                addEdge(entryNode, exitNode)
              case lnt: AlirLocationUriNode =>
                val lt = body.location(lnt.locIndex)
                if(isCall(lt)){
                  val callNodeTarget = getICFGCallNode(callerContext.copy.setContext(calleeSig, lnt.locUri))
                  addEdge(entryNode, callNodeTarget)
                } else {
                  val targetNode = getICFGNormalNode(callerContext.copy.setContext(calleeSig, lnt.locUri))
                  addEdge(entryNode, targetNode)
                }
              case nt =>
                val targetNode = getICFGNormalNode(callerContext.copy.setContext(calleeSig, nt.toString))
                addEdge(entryNode, targetNode)
            }
          case lns: AlirLocationUriNode =>
            val ls = body.location(lns.locIndex)
            e.target match{
              case AlirVirtualNode(label) =>
                if(isCall(ls)){
                  val returnNodeSource = getICFGReturnNode(callerContext.copy.setContext(calleeSig, lns.locUri))
                  addEdge(returnNodeSource, exitNode)
                } else {
                  val sourceNode = getICFGNormalNode(callerContext.copy.setContext(calleeSig, lns.locUri))
                  addEdge(sourceNode, exitNode)
                }
              case lnt: AlirLocationUriNode =>
                val lt = body.location(lnt.locIndex)
                if(isCall(ls)){
                  val returnNodeSource = getICFGReturnNode(callerContext.copy.setContext(calleeSig, lns.locUri))
                  if(isCall(lt)){
                    val callNodeTarget = getICFGCallNode(callerContext.copy.setContext(calleeSig, lnt.locUri))
                    addEdge(returnNodeSource, callNodeTarget)
                  } else {
                    val targetNode = getICFGNormalNode(callerContext.copy.setContext(calleeSig, lnt.locUri))
                    addEdge(returnNodeSource, targetNode)
                  }
                } else {
                  val sourceNode = getICFGNormalNode(callerContext.copy.setContext(calleeSig, lns.locUri))
                  if(isCall(lt)){
                    val callNodeTarget = getICFGCallNode(callerContext.copy.setContext(calleeSig, lnt.locUri))
                    addEdge(sourceNode, callNodeTarget)
                  } else {
                    val targetNode = getICFGNormalNode(callerContext.copy.setContext(calleeSig, lnt.locUri))
                    addEdge(sourceNode, targetNode)
                  }
                }
              case nt =>
                val targetNode = getICFGNormalNode(callerContext.copy.setContext(calleeSig, nt.toString))
                if(isCall(ls)){
                  val returnNodeSource = getICFGReturnNode(callerContext.copy.setContext(calleeSig, lns.locUri))
                  addEdge(returnNodeSource, targetNode)
                } else {
                  val sourceNode = getICFGNormalNode(callerContext.copy.setContext(calleeSig, lns.locUri))
                  addEdge(sourceNode, targetNode)
                }
            }
          case ns =>
            val sourceNode = getICFGNormalNode(callerContext.copy.setContext(calleeSig, ns.toString))
            e.target match{
              case AlirVirtualNode(label) =>
                addEdge(sourceNode, exitNode)
              case lnt: AlirLocationUriNode =>
                val lt = body.location(lnt.locIndex)
                if(isCall(lt)){
                  val callNodeTarget = getICFGCallNode(callerContext.copy.setContext(calleeSig, lnt.locUri))
//                  val returnNodeTarget = getICFGReturnNode(callerContext.copy.setContext(calleeSig, lnt.locUri))
                  addEdge(sourceNode, callNodeTarget)
                } else {
                  val targetNode = getICFGNormalNode(callerContext.copy.setContext(calleeSig, lnt.locUri))
                  addEdge(sourceNode, targetNode)
                }
              case nt =>
                val targetNode = getICFGNormalNode(callerContext.copy.setContext(calleeSig, nt.toString))
                addEdge(sourceNode, targetNode)
            }
        }
      }
      addProcessed(calleeProc.getSignature, callerContext, nodes)
      nodes
    }
  }
  
  def extendGraph(calleeSig: Signature, callerContext: Context): Node = {
    val callNode = getICFGCallNode(callerContext)
    val returnNode = getICFGReturnNode(callerContext)
    val calleeEntryContext = callerContext.copy
    calleeEntryContext.setContext(calleeSig, "Entry")
    val calleeExitContext = callerContext.copy
    calleeExitContext.setContext(calleeSig, "Exit")
    val targetNode = getICFGEntryNode(calleeEntryContext)
    val retSrcNode = getICFGExitNode(calleeExitContext)
    this.synchronized{
      if(!hasEdge(callNode, targetNode))
        addEdge(callNode, targetNode)
      if(!hasEdge(retSrcNode, returnNode))
        addEdge(retSrcNode, returnNode)
    }
    targetNode
  }
  
  def extendGraphOneWay(calleeSig: Signature, callerContext: Context, typ: String = null): Node = {
    val callNode = getICFGCallNode(callerContext)
    val calleeEntryContext = callerContext.copy
    calleeEntryContext.setContext(calleeSig, "Entry")
    val targetNode = getICFGEntryNode(calleeEntryContext)
    this.synchronized{
      this.cg.addCall(callNode.getOwner, targetNode.getOwner)
      if(!hasEdge(callNode, targetNode))
        addEdge(callNode, targetNode, typ)
    }
    targetNode
  }
  
  def toApiGraph(global: Global): InterproceduralControlFlowGraph[Node] = {
    val ns = nodes filter{
      n =>
        n match{
          case cn: ICFGCallNode =>
            cn.getCalleeSet.exists {
              c => 
                val clazz = global.getClassOrResolve(c.callee.getClassType)
                !clazz.isSystemLibraryClass
            }
          case _ => true
        }
    }
    ns foreach(compressByDelNode(_))
    this
  }
  
  def addICFGNormalNode(context: Context): Node = {
    val node = newICFGNormalNode(context).asInstanceOf[Node]
    val n =
      if (pool.contains(node)) pool(node)
      else {
        pl += (node -> node)
        node
      }
    graph.addVertex(n)
    n
  }
  
  def icfgNormalNodeExists(context: Context): Boolean = {
    graph.containsVertex(newICFGNormalNode(context).asInstanceOf[Node])
  }
  
  def getICFGNormalNode(context: Context): Node =
    pool(newICFGNormalNode(context))
  
  protected def newICFGNormalNode(context: Context) =
    ICFGNormalNode(context)
    
  def addICFGCallNode(context: Context): Node = {
    val node = newICFGCallNode(context).asInstanceOf[Node]
    val n =
      if (pool.contains(node)) pool(node)
      else {
        pl += (node -> node)
        node
      }
    graph.addVertex(n)
    n
  }
  
  def icfgCallNodeExists(context: Context): Boolean = {
    graph.containsVertex(newICFGCallNode(context).asInstanceOf[Node])
  }
  
  def getICFGCallNode(context: Context): Node =
    pool(newICFGCallNode(context))
  
  protected def newICFGCallNode(context: Context) =
    ICFGCallNode(context)
    
  def addICFGReturnNode(context: Context): Node = {
    val node = newICFGReturnNode(context).asInstanceOf[Node]
    val n =
      if (pool.contains(node)) pool(node)
      else {
        pl += (node -> node)
        node
      }
    graph.addVertex(n)
    n
  }
  
  def icfgReturnNodeExists(context: Context): Boolean = {
    graph.containsVertex(newICFGReturnNode(context).asInstanceOf[Node])
  }
  
  def getICFGReturnNode(context: Context): Node =
    pool(newICFGReturnNode(context))
  
  protected def newICFGReturnNode(context: Context) =
    ICFGReturnNode(context)
  
    
  def addICFGEntryNode(context: Context): Node = {
    val node = newICFGEntryNode(context).asInstanceOf[Node]
    val n =
      if (pool.contains(node)) pool(node)
      else {
        pl += (node -> node)
        node
      }
    graph.addVertex(n)
    n
  }
  
  def icfgEntryNodeExists(context: Context): Boolean = {
    graph.containsVertex(newICFGEntryNode(context).asInstanceOf[Node])
  }
  
  def getICFGEntryNode(context: Context): Node =
    pool(newICFGEntryNode(context))
  
  protected def newICFGEntryNode(context: Context) =
    ICFGEntryNode(context)
    
  def addICFGCenterNode(context: Context): Node = {
    val node = newICFGCenterNode(context).asInstanceOf[Node]
    val n =
      if (pool.contains(node)) pool(node)
      else {
        pl += (node -> node)
        node
      }
    graph.addVertex(n)
    n
  }
  
  def icfgICFGCenterNodeExists(context: Context): Boolean = {
    graph.containsVertex(newICFGCenterNode(context).asInstanceOf[Node])
  }
  
  def getICFGCenterNode(context: Context): Node =
    pool(newICFGCenterNode(context))
  
  protected def newICFGCenterNode(context: Context) =
    ICFGCenterNode(context)
    
  def addICFGExitNode(context: Context): Node = {
    val node = newICFGExitNode(context).asInstanceOf[Node]
    val n =
      if (pool.contains(node)) pool(node)
      else {
        pl += (node -> node)
        node
      }
    graph.addVertex(n)
    n
  }
  
  def icfgExitNodeExists(context: Context): Boolean = {
    graph.containsVertex(newICFGExitNode(context).asInstanceOf[Node])
  }
  
  def getICFGExitNode(context: Context): Node =
    pool(newICFGExitNode(context))
  
  protected def newICFGExitNode(context: Context) =
    ICFGExitNode(context)
  
}

sealed abstract class ICFGNode(context: Context) extends InterproceduralNode(context){
  protected var owner: Signature = null
  protected var loadedClassBitSet: BitSet = BitSet.empty
//  protected var code: String = null
  def setOwner(owner: Signature)  = this.owner = owner
  def getOwner = this.owner
//  def setCode(code: String) = this.code = code
//  def getCode: String = this.code
  def setLoadedClassBitSet(bitset: BitSet) = this.loadedClassBitSet = bitset
  def getLoadedClassBitSet = this.loadedClassBitSet
  
//  def updateLoadedClassBitSet(bitset: BitSet) = {
//    if(getLoadedClassBitSet == BitSet.empty) setLoadedClassBitSet(bitset)
//    else setLoadedClassBitSet(bitset.intersect(getLoadedClassBitSet))
//  }
}

abstract class ICFGVirtualNode(context: Context) extends ICFGNode(context) {
  def getVirtualLabel: String
  
  override def toString: String = getVirtualLabel + "@" + context.getMethodSig
}

final case class ICFGEntryNode(context: Context) extends ICFGVirtualNode(context){
//  this.code = "Entry: " + context.getMethodSig
  def getVirtualLabel: String = "Entry"
}

final case class ICFGExitNode(context: Context) extends ICFGVirtualNode(context){
//  this.code = "Exit: " + context.getMethodSig
  def getVirtualLabel: String = "Exit"
}

final case class ICFGCenterNode(context: Context) extends ICFGVirtualNode(context){
//  this.code = "L0000: Center;"
  def getVirtualLabel: String = "Center"
}

abstract class ICFGLocNode(context: Context) extends ICFGNode(context) {
  def getLocUri: String = context.getLocUri
  protected val LOC_INDEX = "LocIndex"
  def setLocIndex(i: Int) = setProperty(LOC_INDEX, i)
  def getLocIndex: Int = getPropertyOrElse[Int](LOC_INDEX, throw new RuntimeException("did not have loc index"))
}

abstract class ICFGInvokeNode(context: Context) extends ICFGLocNode(context) {
  final val CALLEES = "callee_set"
  final val CALLEE_SIG = "callee_sig"
  final val CALL_TYPE = "call_type"
  def getInvokeLabel: String
  def setCalleeSet(calleeSet: ISet[Callee]) = this.setProperty(CALLEES, calleeSet)
  def addCallee(callee: Callee) = this.setProperty(CALLEES, getCalleeSet + callee)
  def addCallees(calleeSet: ISet[Callee]) = this.setProperty(CALLEES, getCalleeSet ++ calleeSet)
  def getCalleeSet: ISet[Callee] = this.getPropertyOrElse(CALLEES, isetEmpty)
  def setCalleeSig(calleeSig: Signature) = {
    this.setProperty(CALLEE_SIG, calleeSig)
  }
  def getCalleeSig: Signature = this.getPropertyOrElse(CALLEE_SIG, throw new RuntimeException("Callee sig did not set for " + this))
  def setCallType(callType: String) = {
    this.setProperty(CALL_TYPE, callType)
  }
  def getCallType: String = this.getPropertyOrElse(CALL_TYPE, throw new RuntimeException("Call type did not set for " + this))
  override def toString: String = getInvokeLabel + "@" + context
  var argNames: IList[String] = ilistEmpty
  var retNames: IList[String] = ilistEmpty
}

final case class ICFGCallNode(context: Context) extends ICFGInvokeNode(context){
  def getInvokeLabel: String = "Call"
}

final case class ICFGReturnNode(context: Context) extends ICFGInvokeNode(context){
  def getInvokeLabel: String = "Return"
}

final case class ICFGNormalNode(context: Context) extends ICFGLocNode(context){
  override def toString: String = context.toString
}
