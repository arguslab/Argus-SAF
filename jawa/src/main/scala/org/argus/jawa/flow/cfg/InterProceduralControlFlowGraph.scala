/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.cfg

import org.argus.jawa.core.ast.{CallStatement, Location}
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util._
import org.argus.jawa.core.{Global, JawaMethod}
import org.argus.jawa.flow.cg.CallGraph
import org.argus.jawa.flow.interprocedural.{CallHandler, Callee, RFACallee}
import org.argus.jawa.flow.pta.PTAResult
import org.argus.jawa.flow.{AlirLoc, Context, InterProceduralNode, JawaAlirInfoProvider}

import scala.collection.immutable.BitSet

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class InterProceduralControlFlowGraph[Node <: ICFGNode] extends ControlFlowGraph[Node]{
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
    
  protected var entryN: Node = _

  protected var exitN: Node = _
  
  def addEntryNode(en: Node): Unit = this.entryN = en
  def addExitNode(en: Node): Unit = this.exitN = en
  
  def entryNode: Node = this.entryN

  def exitNode: Node = this.exitN

  private val cg: CallGraph = new CallGraph
  
  def getCallGraph: CallGraph = this.cg
  
  private val processed: MMap[(Signature, Context), ISet[Node]] = cmapEmpty
  
  def isProcessed(proc: Signature, callerContext: Context): Boolean = processed.contains(proc, callerContext)
  
  def addProcessed(jp: Signature, c: Context, nodes: ISet[Node]): Unit = {
    this.processed += ((jp, c) -> nodes)
  }
  
  def getProcessed: IMap[(Signature, Context), ISet[Node]] = this.processed.toMap
  
  def entryNode(proc: Signature, callerContext: Context): Node = {
    require(isProcessed(proc, callerContext), "ICFG EntryNode: " + proc + " should already be processed.")
    processed(proc, callerContext).foreach{
      n => if(n.isInstanceOf[ICFGEntryNode]) return n
    }
    throw new RuntimeException("Cannot find entry node for: " + proc)
  }
  
  def reverse: InterProceduralControlFlowGraph[Node] = {
    val result = new InterProceduralControlFlowGraph[Node]
    for (n <- nodes) result.addNode(n)
    for (e <- edges) result.addEdge(e.target, e.source)
    result.entryN = this.exitNode
    result.exitN = this.entryNode
    result
  }

  override def toString: String = {
    val sb = new StringBuilder("CFG\n")
    for (n <- nodes)
      for (m <- successors(n)) {
        for (_ <- getEdges(n, m)) {
          sb.append(s"${n.toString} -> ${m.toString}\n")
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
  def compressByDelNode (n: Node): Unit = {
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
   
  def isCall(l: Location): Boolean = l.statement.isInstanceOf[CallStatement]
   
  def merge(icfg: InterProceduralControlFlowGraph[Node]): Any = {
    icfg.nodes.foreach(addNode)
    icfg.edges.foreach(addEdge)
    icfg.getCallGraph.getCallMap.foreach{
      case (src, dsts) =>
        cg.addCalls(src, cg.getCallMap.getOrElse(src, isetEmpty) ++ dsts)
    }
    this.processed ++= icfg.processed
  }

  def buildWithExisting(application: FileResourceUri, methods: IList[JawaMethod], ptaresult: PTAResult): Unit = {
    Context.init_context_length(0)
    val callMap: MMap[Context, ISet[RFACallee]] = mmapEmpty
    methods foreach { method =>
      if (method.isConcrete && method.getDeclaringClass.isApplicationClass) {
        val context = new Context(application)
        val nodes = collectCfgToBaseGraph(method, context, isFirst = true, needReturnNode = true)
        nodes foreach {
          case call: ICFGCallNode =>
            val uri = call.getContext.getCurrentLocUri
            val cs = method.getBody.resolvedBody.location(uri).statement.asInstanceOf[CallStatement]
            val callees = CallHandler.getCalleeSet(method.declaringClass.global, cs, call.getContext, ptaresult)
            call.setCalleeSet(callees.map(_.asInstanceOf[Callee]))
            callMap(call.getContext) = callees.filter { callee =>
              method.declaringClass.global.getMethod(callee.callee) match {
                case Some(m) =>
                  m.isConcrete && m.declaringClass.isApplicationClass
                case None => false
              }
            }
          case _ =>
        }
      }
    }
  }
  
  def collectCfgToBaseGraph(calleeProc: JawaMethod, callerContext: Context, isFirst: Boolean, needReturnNode: Boolean): ISet[Node] = {
    val calleeSig = calleeProc.getSignature
    val body = calleeProc.getBody.resolvedBody
    val cfg = JawaAlirInfoProvider.getCfg(calleeProc)
    var nodes = isetEmpty[Node]
    cfg.nodes map {
      case CFGVirtualNode(label) =>
        label match {
          case "Entry" =>
            val entryNode = addICFGEntryNode(callerContext.copy.setContext(calleeSig, "Entry"))
            entryNode.setOwner(calleeProc.getSignature)
            entryNode.asInstanceOf[ICFGVirtualNode].thisName = calleeProc.thisOpt
            entryNode.asInstanceOf[ICFGVirtualNode].paramNames ++= calleeProc.params.map(_._1)
            nodes += entryNode
            if (isFirst) this.entryN = entryNode
          case "Exit" =>
            val exitNode = addICFGExitNode(callerContext.copy.setContext(calleeSig, "Exit"))
            exitNode.setOwner(calleeProc.getSignature)
            exitNode.asInstanceOf[ICFGVirtualNode].thisName = calleeProc.thisOpt
            exitNode.asInstanceOf[ICFGVirtualNode].paramNames ++= calleeProc.params.map(_._1)
            nodes += exitNode
            if (isFirst) this.exitN = exitNode
          case a => throw new RuntimeException("unexpected virtual label: " + a)
        }
      case ln: CFGLocationNode =>
        val l = body.locations(ln.locIndex)
        if (isCall(l)) {
          val cs = l.statement.asInstanceOf[CallStatement]
          val c = addICFGCallNode(callerContext.copy.setContext(calleeSig, ln.locUri))
          c.setOwner(calleeProc.getSignature)
          c.asInstanceOf[ICFGInvokeNode].recvNameOpt = cs.recvOpt
          c.asInstanceOf[ICFGInvokeNode].argNames = cs.args
          c.asInstanceOf[ICFGInvokeNode].retNameOpt = cs.lhsOpt.map(lhs => lhs.name)
          c.asInstanceOf[ICFGLocNode].setLocIndex(ln.locIndex)
          c.asInstanceOf[ICFGLocNode].setCode(l.toCode)
          c.asInstanceOf[ICFGInvokeNode].setCalleeSig(cs.signature)
          c.asInstanceOf[ICFGInvokeNode].setCallType(cs.kind)
          nodes += c
          if(needReturnNode) {
            val r = addICFGReturnNode(callerContext.copy.setContext(calleeSig, ln.locUri))
            r.setOwner(calleeProc.getSignature)
            r.asInstanceOf[ICFGInvokeNode].recvNameOpt = cs.recvOpt
            r.asInstanceOf[ICFGInvokeNode].argNames = cs.args
            r.asInstanceOf[ICFGInvokeNode].retNameOpt = cs.lhsOpt.map(lhs => lhs.name)
            r.asInstanceOf[ICFGLocNode].setLocIndex(ln.locIndex)
            r.asInstanceOf[ICFGLocNode].setCode(l.toCode)
            r.asInstanceOf[ICFGInvokeNode].setCalleeSig(cs.signature)
            r.asInstanceOf[ICFGInvokeNode].setCallType(cs.kind)
            nodes += r
            addEdge(c, r)
          }
        } else {
          val node = addICFGNormalNode(callerContext.copy.setContext(calleeSig, ln.locUri))
          node.setOwner(calleeProc.getSignature)
          node.asInstanceOf[ICFGLocNode].setLocIndex(ln.locIndex)
          node.asInstanceOf[ICFGLocNode].setCode(l.toCode)
          nodes += node
        }
    }
    for (e <- cfg.edges) {
      val entryNode = getICFGEntryNode(callerContext.copy.setContext(calleeSig, "Entry"))
      val exitNode = getICFGExitNode(callerContext.copy.setContext(calleeSig, "Exit"))
      e.source match {
        case _: CFGVirtualNode =>
          e.target match{
            case _: CFGVirtualNode =>
              addEdge(entryNode, exitNode)
            case lnt: CFGLocationNode =>
              val lt = body.locations(lnt.locIndex)
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
        case lns: CFGLocationNode =>
          val ls = body.locations(lns.locIndex)
          e.target match{
            case CFGVirtualNode(_) =>
              if(isCall(ls)){
                val nodeSource =
                  if(needReturnNode) getICFGReturnNode(callerContext.copy.setContext(calleeSig, lns.locUri))
                  else getICFGCallNode(callerContext.copy.setContext(calleeSig, lns.locUri))
                addEdge(nodeSource, exitNode)
              } else {
                val sourceNode = getICFGNormalNode(callerContext.copy.setContext(calleeSig, lns.locUri))
                addEdge(sourceNode, exitNode)
              }
            case lnt: CFGLocationNode =>
              val lt = body.locations(lnt.locIndex)
              if(isCall(ls)){
                val nodeSource =
                  if(needReturnNode) getICFGReturnNode(callerContext.copy.setContext(calleeSig, lns.locUri))
                  else getICFGCallNode(callerContext.copy.setContext(calleeSig, lns.locUri))
                if(isCall(lt)){
                  val callNodeTarget = getICFGCallNode(callerContext.copy.setContext(calleeSig, lnt.locUri))
                  addEdge(nodeSource, callNodeTarget)
                } else {
                  val targetNode = getICFGNormalNode(callerContext.copy.setContext(calleeSig, lnt.locUri))
                  addEdge(nodeSource, targetNode)
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
                val nodeSource =
                  if(needReturnNode) getICFGReturnNode(callerContext.copy.setContext(calleeSig, lns.locUri))
                  else getICFGCallNode(callerContext.copy.setContext(calleeSig, lns.locUri))
                addEdge(nodeSource, targetNode)
              } else {
                val sourceNode = getICFGNormalNode(callerContext.copy.setContext(calleeSig, lns.locUri))
                addEdge(sourceNode, targetNode)
              }
          }
      }
    }
    addProcessed(calleeProc.getSignature, callerContext, nodes)
    nodes
  }
  
  def extendGraph(calleeSig: Signature, callerContext: Context, needReturnNode: Boolean): Node = {
    val callNode = getICFGCallNode(callerContext)
    val returnNode =
      if(needReturnNode) getICFGReturnNode(callerContext)
      else callNode
    val calleeEntryContext = callerContext.copy
    calleeEntryContext.setContext(calleeSig, "Entry")
    val calleeExitContext = callerContext.copy
    calleeExitContext.setContext(calleeSig, "Exit")
    val targetNode = getICFGEntryNode(calleeEntryContext)
    val retSrcNode = getICFGExitNode(calleeExitContext)
    if(!hasEdge(callNode, targetNode))
      addEdge(callNode, targetNode)
    if(!hasEdge(retSrcNode, returnNode))
      addEdge(retSrcNode, returnNode)
    targetNode
  }
  
  def toApiGraph(global: Global): InterProceduralControlFlowGraph[Node] = {
    val ns = nodes filter{ n =>
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
    ns foreach compressByDelNode
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

sealed abstract class ICFGNode(context: Context) extends InterProceduralNode(context){
  protected var loadedClassBitSet: BitSet = BitSet.empty
  def setLoadedClassBitSet(bitset: BitSet): Unit = this.loadedClassBitSet = bitset
  def getLoadedClassBitSet: IBitSet = this.loadedClassBitSet
}

abstract class ICFGVirtualNode(context: Context) extends ICFGNode(context) {
  def getVirtualLabel: String
  var thisName: Option[String] = None
  var paramNames: IList[String] = ilistEmpty
  override def toString: String = getVirtualLabel + "@" + context.getMethodSig
}

final case class ICFGEntryNode(context: Context) extends ICFGVirtualNode(context){
  def getVirtualLabel: String = "Entry"
}

final case class ICFGExitNode(context: Context) extends ICFGVirtualNode(context){
  def getVirtualLabel: String = "Exit"
}

final case class ICFGCenterNode(context: Context) extends ICFGVirtualNode(context){
  def getVirtualLabel: String = "Center"
}

abstract class ICFGLocNode(context: Context) extends ICFGNode(context) with AlirLoc {
  def locUri: String = context.getLocUri
  protected val LOC_INDEX = "LocIndex"
  def setLocIndex(i: Int): Option[Int] = setProperty(LOC_INDEX, i)
  def locIndex: Int = getProperty[Int](LOC_INDEX)
  protected val CODE = "Code"
  def setCode(str: String): Option[String] = setProperty(CODE, str)

  override def toString: String = getProperty[String](CODE)
}

abstract class ICFGInvokeNode(context: Context) extends ICFGLocNode(context) {
  final val CALLEES = "callee_set"
  final val CALLEE_SIG = "callee_sig"
  final val CALL_TYPE = "call_type"
  def getInvokeLabel: String
  def setCalleeSet(calleeSet: ISet[Callee]): Unit = this.setProperty(CALLEES, calleeSet)
  def addCallee(callee: Callee): Unit = this.setProperty(CALLEES, getCalleeSet + callee)
  def addCallees(calleeSet: ISet[Callee]): Unit = this.setProperty(CALLEES, getCalleeSet ++ calleeSet)
  def getCalleeSet: ISet[Callee] = this.getPropertyOrElse(CALLEES, isetEmpty)
  def setCalleeSig(calleeSig: Signature): Option[Signature] = {
    this.setProperty(CALLEE_SIG, calleeSig)
  }
  def getCalleeSig: Signature = this.getPropertyOrElse(CALLEE_SIG, throw new RuntimeException("Callee sig did not set for " + this))
  def setCallType(callType: String): Option[String] = {
    this.setProperty(CALL_TYPE, callType)
  }
  def getCallType: String = this.getPropertyOrElse(CALL_TYPE, throw new RuntimeException("Call type did not set for " + this))

  var recvNameOpt: Option[String] = None
  var argNames: IList[String] = ilistEmpty
  var retNameOpt: Option[String] = None
  def allArgs: IList[String] = (recvNameOpt ++ argNames).toList
}

final case class ICFGCallNode(context: Context) extends ICFGInvokeNode(context){
  def getInvokeLabel: String = "Call"
}

final case class ICFGReturnNode(context: Context) extends ICFGInvokeNode(context){
  def getInvokeLabel: String = "Return"
}

final case class ICFGNormalNode(context: Context) extends ICFGLocNode(context)
