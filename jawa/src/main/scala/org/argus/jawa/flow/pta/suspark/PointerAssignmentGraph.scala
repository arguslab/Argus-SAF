/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.pta.suspark

import org.argus.jawa.core.util._
import org.argus.jawa.flow._
import org.argus.jawa.flow.interprocedural._
import org.argus.jawa.flow.pta._
import org.argus.jawa.core._
import org.argus.jawa.core.elements.{JavaKnowledge, JawaType, Signature}

import scala.collection.mutable

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class PointsToMap extends PTAResult {

  final val TITLE = "PointsToMap"

  /**
    * e.g. L0: p = q; L1:  r = p; transfer means p@L0 -> p@L1
    */
  def transferPointsToSet(n1: PtaNode, n2: PtaNode): Unit = {
    n2.getSlots(this) foreach {
      addInstances(n2.getContext, _, pointsToSet(n1))
    }
  }

  /**
    * e.g. L0: p = q; L1:  r = p; transfer means p@L0 -> p@L1
    */
  def transferPointsToSet(n: PtaNode, d: ISet[Instance]): Unit = {
    n.getSlots(this) foreach {
      addInstances(n.getContext, _, d)
    }
  }

  val heapContext: Context = new Context(TITLE)
  heapContext.setContext(new Signature("LPAG;.heap:()V"), "heap")

  /**
    * n1 -> n2 or n1.f -> n2 or n1[] -> n2, n1 -> n2.f, n1 -> n2[]
    */
  def propagatePointsToSet(n1: PtaNode, n2: PtaNode): Unit = {
    n2.getSlots(this) foreach {
      case arr: ArraySlot =>
        addInstances(heapContext, arr, pointsToSet(n1))
      case fie: FieldSlot =>
        addInstances(heapContext, fie, pointsToSet(n1))
      case slot =>
        setInstances(n2.getContext, slot, pointsToSet(n1))
    }
  }

  /**
    * n or n.f or n[] or @@n
    */
  def pointsToSet(n: PtaNode): ISet[Instance] = {
    val slots = n.getSlots(this)
    if (slots.nonEmpty) {
      slots.map {
        case s@(_: ArraySlot) => pointsToSet(heapContext, s)
        case s@(_: FieldSlot) => pointsToSet(heapContext, s)
        case s => pointsToSet(n.getContext, s)
      }.reduce(iunion[Instance])
    } else isetEmpty
  }

  def isDiff(n1: PtaNode, n2: PtaNode): Boolean = {
    pointsToSet(n1) != pointsToSet(n2)
  }

  def contained(n1: PtaNode, n2: PtaNode): Boolean = {
    (pointsToSet(n1) -- pointsToSet(n2)).isEmpty
  }

  def getDiff(n1: PtaNode, n2: PtaNode): ISet[Instance] = {
    pointsToSet(n1) diff pointsToSet(n2)
  }
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class PointerAssignmentGraph[Node <: PtaNode]
    extends AlirGraphImpl[Node]
    with AlirSuccPredAccesses[Node]
    with AlirEdgeAccesses[Node]
    with PAGConstraint {

  val pointsToMap = new PointsToMap
  
  private val processed: MMap[(Signature, Context), Point with Method] = new mutable.HashMap[(Signature, Context), Point with Method]
  
  def isProcessed(proc: Signature, callerContext: Context): Boolean = processed.contains(proc, callerContext)
  
  def getPointMethod(proc: Signature, callerContext: Context): Point with Method =  processed(proc, callerContext)
  
  def addProcessed(jp: Signature, c: Context, ps: Set[Point]): Unit = {
    ps.foreach {
      case point: Point with Method => this.processed += ((jp, c) -> point)
      case _ =>
    }
  }
  
  def getProcessed: IMap[(Signature, Context), Point with Method] = this.processed.toMap
  
  private val newNodes: MSet[Node] = msetEmpty
  private val newEdges: MSet[Edge] = msetEmpty

  case class PTACallee(callee: Signature, pi: Point with Invoke, node: Node) extends Callee
  
  def processObjectAllocation(): Unit = {
    newEdges.foreach{ edge =>
      getEdgeType(edge) match {
        case EdgeType.ALLOCATION =>
          if(pointsToMap.isDiff(edge.source, edge.target)){
            pointsToMap.propagatePointsToSet(edge.source, edge.target)
            worklist += edge.target
          }
        case _ =>
      }
    }
    newEdges.clear()
  }

  def getStaticCallWithNoParam: ISet[PtaNode] = {
    val nodes: MSet[PtaNode] = msetEmpty
    newNodes.foreach { node =>
      node.point match {
        case pi: Point with Invoke =>
          if(pi.invokeTyp.equals("static") && pi.sig.getParameterNum == 0) {
            nodes += node
          }
        case _ =>
      }
    }
    newNodes.clear()
    nodes.toSet
  }
  
  def handleModelCall(pi: Point with Invoke, context: Context, callee: Callee): Unit = {
    callee.callee.getReturnType match {
      case ot: JawaType =>
        val pinode = getNode(pi, context)
        pinode.getSlots(pointsToMap).foreach { s =>
          pointsToMap.addInstance(context, s, PTAInstance(ot.toUnknown, context))
          worklist += pinode
        }
      case _ =>
    }
  }
  
  def addEdge(source: Node, target: Node, typ: EdgeType.Value): Edge = {
    val edge = graph.addEdge(getNode(source), getNode(target))
    edge.setProperty(EDGE_TYPE, typ)
    edge
  }
  
  def getEdgeType(edge: Edge): EdgeType.Value = {
    assume(edge.propertyMap.contains(EDGE_TYPE))
    edge.getProperty[EdgeType.Value](EDGE_TYPE)
  }
  
  final val EDGE_TYPE = "EdgeType"
  final val PARAM_NUM = "ParamNumber"
  
  final val worklist: MList[Node] = mlistEmpty
    
  /**
   * combine two pags into one.
   */ 
  def combinePags(pag2: PointerAssignmentGraph[Node]): Unit = {
    pag2.nodes.foreach(addNode)
    pag2.edges.foreach(addEdge)
    this.processed ++= pag2.getProcessed
    worklist ++= pag2.worklist
  }
  
  
  /**
   * create the nodes and edges to reflect the constraints corresponding 
   * to the given program point. If a value is added to a node, then that 
   * node is added to the worklist.
   */
  def constructGraph(ap: JawaMethod, ps: Set[Point], callerContext: Context, entryPoint: Boolean): Unit = {
    addProcessed(ap.getSignature, callerContext, ps)
    ps.foreach { p =>
      newNodes ++= collectNodes(ap, p, callerContext, entryPoint)
    }
    ps.foreach { p =>
      val cfg = JawaAlirInfoProvider.getCfg(ap)
      val rda = JawaAlirInfoProvider.getRda(ap, cfg)
      val constraintMap = applyConstraint(p, ps, cfg, rda)
      newEdges ++= buildingEdges(constraintMap, ap.getSignature, callerContext)
    }
  }

  def collectNodes(ap: JawaMethod, p: Point, callerContext: Context, entryPoint: Boolean): ISet[Node] = {
    val nodes: MSet[Node] = msetEmpty
    val pSig = ap.getSignature
    val context = callerContext.copy
    p match {
      case lp: Point with Loc => context.setContext(pSig, lp.locUri)
      case _ => context.setContext(pSig, p.ownerSig.signature)
    }
    
    p match {
      case cp: PointCall =>
        val lhsopt = cp.lhsOpt
        val rhs = cp.rhs
        lhsopt foreach { nodes += getNodeOrElse(_, context) }
        val rhsNode = getNodeOrElse(rhs, context)
        nodes += rhsNode
        rhs match {
          case pi: Point with Invoke =>
            pi match {
              case vp: Point with Invoke with Virtual =>
                nodes += getNodeOrElse(vp.recvPCall, context)
                nodes += getNodeOrElse(vp.recvPReturn, context)
              case _ =>
                worklist += rhsNode
            }
            val args_Entry = pi.argPsCall
            val args_Exit = pi.argPsReturn
            args_Entry.foreach{
              case (_, pa) =>
                val argNode = getNodeOrElse(pa, context)
                nodes += argNode
                argNode.setProperty(PARAM_NUM, pa.index)
            }
            args_Exit.foreach{
              case (_, pa) =>
                val argNode = getNodeOrElse(pa, context)
                nodes += argNode
                argNode.setProperty(PARAM_NUM, pa.index)
            }
          case _ =>
        }
      case asmtP: PointAsmt =>
        val lhs = asmtP.lhs
        val rhs = asmtP.rhs
        val lhsNode = getNodeOrElse(lhs, context)
        nodes += lhsNode
        val rhsNode = getNodeOrElse(rhs, context)
        nodes += rhsNode
        lhs match {
          case pfl: PointFieldL =>
            val fieldNode = getNodeOrElse(pfl, context)
            nodes += fieldNode
            val baseNode = getNodeOrElse(pfl.baseP, context)
            nodes += baseNode
          case _ =>
        }
        rhs match {
          case pgr: PointStaticFieldR =>
            val globalVarNode = getNodeOrElse(pgr, context)
            nodes += globalVarNode
          case pfr: PointFieldR =>
            val fieldNode = getNodeOrElse(pfr, context)
            nodes += fieldNode
            val baseNode = getNodeOrElse(pfr.baseP, context)
            nodes += baseNode
          case _: PointClassO =>
            val ins = PTAInstance(JavaKnowledge.CLASS, context)
            pointsToMap.addInstance(context, InstanceSlot(ins), ins)
          case per: PointExceptionR =>
            val ins = PTAInstance(per.typ, context)
            pointsToMap.addInstance(context, InstanceSlot(ins), ins)
          case pso: PointStringO =>
            val ins = PTAConcreteStringInstance(pso.text, context)
            pointsToMap.addInstance(context, InstanceSlot(ins), ins)
          case po: PointO =>
            val ins = PTAInstance(po.obj, context)
            pointsToMap.addInstance(context, InstanceSlot(ins), ins)
          case _ =>
        }
      case procP: Point with Method =>
        procP match {
          case vp: Point with Method with Dynamic =>
            val node = getNodeOrElse(vp.thisPEntry, context)
            nodes += node
            if(entryPoint) {
              val tName = ap.thisOpt.getOrElse("this")
              val ins = PTAInstance(ap.declaringClass.getType.toUnknown, context)
              pointsToMap.addInstance(context, VarSlot(tName), ins)
              worklist += node
            }
            nodes += getNodeOrElse(vp.thisPExit, context)
          case _ =>
        }
        procP.retVar match {
          case Some(rev) =>
            nodes += getNodeOrElse(rev, context)
          case None =>
        }
        val params_Entry = procP.paramPsEntry
        val params_Exit = procP.paramPsExit
        params_Entry.foreach{
          case (_, pa) => 
            val paramNode = getNodeOrElse(pa, context)
            nodes += paramNode
            paramNode.setProperty(PARAM_NUM, pa.index)
            if(entryPoint) {
              val (pName, pType) = ap.params(pa.index)
              pType match {
                case ot: JawaType =>
                  val ins = PTAInstance(ot.toUnknown, context)
                  pointsToMap.addInstance(context, VarSlot(pName), ins)
                  worklist += paramNode
              }
            }
        }
        params_Exit.foreach{
          case (_, pa) =>
            val paramNode = getNodeOrElse(pa, context)
            nodes += paramNode
            paramNode.setProperty(PARAM_NUM, pa.index)
        }
      case retP: PointRet =>
        nodes += getNodeOrElse(retP, context)
      case _ =>
    }
    nodes.toSet
  }
  
  def buildingEdges(map: MMap[EdgeType.Value, MMap[Point, MSet[Point]]], pSig: Signature, context: Context): Set[Edge] = {
    var edges: Set[Edge] = isetEmpty
    map.foreach{
      case(typ, edgeMap) =>
        edgeMap.foreach{
          case(src, dsts) =>
            val s = context.copy
            src match {
              case lp: Point with Loc => s.setContext(pSig, lp.locUri)
              case _ => s.setContext(pSig, src.ownerSig.signature)
            }
            val srcNode = getNode(src, s)
            dsts.foreach{ dst =>
              val t = context.copy
              dst match {
                case lp: Point with Loc => t.setContext(pSig, lp.locUri)
                case _ => t.setContext(pSig, dst.ownerSig.signature)
              }
              val targetNode = getNode(dst, t)
              if(!graph.containsEdge(srcNode, targetNode)) {
                edges += addEdge(srcNode, targetNode, typ)
              }
            }
        }
    }
    edges
  }
  
  def breakPiEdges(pi: Point with Invoke, calleeAccessTyp: String, srcContext: Context): Unit = {
    pi match {
      case vp: Point with Invoke with Virtual =>
        if(calleeAccessTyp != null){
          val srcNode = getNode(vp.recvPCall, srcContext)
          val targetNode = getNode(vp.recvPReturn, srcContext)
          if(hasEdge(srcNode, targetNode))
            deleteEdge(srcNode, targetNode)
        }
      case _ =>
    }
    
    pi.argPsCall foreach{
      case (_, aCall) =>
        pi.argPsReturn foreach{
          case (_, aReturn) =>
            if(aCall.index == aReturn.index){
              val srcNode = getNode(aCall, srcContext)
              val targetNode = getNode(aReturn, srcContext)
              if(hasEdge(srcNode, targetNode))
                deleteEdge(srcNode, targetNode)
            }
        }
        
    }
  }
  
  private def connectCallEdges(met: Point with Method, pi: Point with Invoke, srcContext: Context) = {
    val targetContext = srcContext.copy
    targetContext.setContext(met.methodSig, met.ownerSig.signature)
    met.paramPsEntry.foreach{
      case (_, paramp) => 
        pi.argPsCall.foreach{
          case (_, argp) =>
            if(paramp.index == argp.index){
              val srcNode = getNode(argp, srcContext)
              val targetNode = getNode(paramp, targetContext)
              worklist += srcNode
              if(!graph.containsEdge(srcNode, targetNode))
                addEdge(srcNode, targetNode, EdgeType.TRANSFER)
            }
          
        }
    }
    met.paramPsExit.foreach{
      case (_, paramp) =>
        pi.argPsReturn.foreach{
          case (_, argp) =>
            if(paramp.index == argp.index){
              val srcNode = getNode(argp, srcContext)
              val targetNode = getNode(paramp, targetContext)
              worklist += srcNode
              if(!graph.containsEdge(srcNode, targetNode))
                addEdge(srcNode, targetNode, EdgeType.TRANSFER)
            }
          
        }
    }
    
    met match {
      case vp: Point with Method with Dynamic =>
        assume(pi.isInstanceOf[PointI])
        val srcNodeCall = getNode(pi.asInstanceOf[PointI].recvPCall, srcContext)
        val targetNodeEntry = getNode(vp.thisPEntry, targetContext)
        worklist += srcNodeCall
        if(!graph.containsEdge(srcNodeCall, targetNodeEntry))
          addEdge(srcNodeCall, targetNodeEntry, EdgeType.THIS_TRANSFER)
        val srcNodeExit = getNode(vp.thisPExit, targetContext)
        val targetNodeReturn = getNode(pi.asInstanceOf[PointI].recvPReturn, srcContext)
        worklist += srcNodeExit
        if(!graph.containsEdge(srcNodeExit, targetNodeReturn))
          addEdge(srcNodeExit, targetNodeReturn, EdgeType.TRANSFER)
      case _ =>
    }
    
    met.retVar match {
      case Some(retv) =>
        val targetNode = getNode(pi, srcContext)
        val srcNode = getNode(retv, targetContext)
        worklist += srcNode
        if(!graph.containsEdge(srcNode, targetNode))
          addEdge(srcNode, targetNode, EdgeType.TRANSFER)
      case None =>
    }
  }
  
  def extendGraph(met: Point with Method, pi: Point with Invoke, srcContext: Context): Unit = {
    breakPiEdges(pi, met.accessTyp, srcContext)
    connectCallEdges(met, pi, srcContext)
  }
  
  def updateContext(callerContext: Context): Unit = {
    this.nodes.foreach{ node =>
      node.getContext.updateContext(callerContext)
    }
  }

  val trackPi: MMap[Point with Invoke, Int] = mmapEmpty
  def updatePiTrackAndGet(pc: Point with Arg with Call): Option[Point with Invoke] = {
    val num = trackPi.getOrElseUpdate(pc.getContainer, 0)
    var piNum = pc.getContainer.sig.getParameterNum
    pc match {
      case _: Point with Virtual => piNum += 1
      case _ =>
    }
    if(num == piNum) {
      Some(pc.getContainer)
    } else {
      trackPi(pc.getContainer) = num + 1
      None
    }
  }

  val argPointInstances: MMap[Point with Arg with Call, MSet[Instance]] = mmapEmpty
  def updateArgPointInstances(pc: Point with Arg with Call, inss: ISet[Instance]): Unit = {
    val set = argPointInstances.getOrElseUpdate(pc, msetEmpty)
    set ++= inss
  }
  def getArgPointInstances(p: Point with Arg with Call): ISet[Instance] = {
    argPointInstances.getOrElse(p, msetEmpty).toSet
  }
  
  def getNodeOrElse(p: Point, context: Context): Node = {
    if(!nodeExists(p, context)) addNode(p, context)
    else getNode(p, context)
  }
  
  def nodeExists(point: Point, context: Context): Boolean = {
    graph.containsVertex(newNode(point, context).asInstanceOf[Node])
  }
  
  def addNode(point: Point, context: Context): Node = {
    val node = newNode(point, context).asInstanceOf[Node]
    val n =
      if (pool.contains(node)) pool(node)
      else {
        pl += (node -> node)
        node
      }
    graph.addVertex(n)
    n
  }
  
  def getNode(point: Point, context: Context): Node = pool(newNode(point, context))
  
  protected def newNode(point: Point, context: Context) = PtaNode(point, context)

  override def toString: String = {
      val sb = new StringBuilder("PAG\n")
      for (n <- nodes) {
        for (m <- successors(n)) {
          for (_ <- getEdges(n, m)) {
            sb.append("%s -> %s\n".format(n, m))
          }
        }
      }
      sb.append("\n")
      sb.toString.trim
  }
}

final case class PtaNode(point: Point, context: Context) extends InterProceduralNode(context) {
  def getSlots(ptaResult: PTAResult): ISet[PTASlot] = {
    point match {
      case po: PointO =>
        Set(InstanceSlot(PTAInstance(po.obj, context)))
      case pso: PointStringO =>
        Set(InstanceSlot(PTAConcreteStringInstance(pso.text, context)))
      case _: PointClassO =>
        Set(InstanceSlot(PTAInstance(JavaKnowledge.CLASS, context)))
      case per: PointExceptionR =>
        Set(InstanceSlot(PTAInstance(per.typ, context)))
      case gla: Point with Loc with Static_Field with MyArray =>
        val pts = ptaResult.pointsToSet(context, StaticFieldSlot(gla.staticFieldFQN.fqn))
        pts.map{ ins =>
          ArraySlot(ins)
        }
      case glo: Point with Loc with Static_Field =>
        Set(StaticFieldSlot(glo.staticFieldFQN.fqn))
      case arr: PointMyArrayL =>
        val pts = ptaResult.pointsToSet(context, VarSlot(arr.arrayname))
        pts.map{ ins =>
          ArraySlot(ins)
        }
      case arr: PointMyArrayR =>
        val pts = ptaResult.pointsToSet(context, VarSlot(arr.arrayname))
        pts.map{ ins =>
          ArraySlot(ins)
        }
      case fie: Point with Loc with Field =>
        val pts = ptaResult.pointsToSet(context, VarSlot(fie.baseP.baseName))
        pts.map{ ins =>
          FieldSlot(ins, fie.fqn.fieldName)
        }
      case bas: Point with Loc with Base =>
        Set(VarSlot(bas.baseName))
      case pl: PointL =>
        Set(VarSlot(pl.varname))
      case pc: PointCastR =>
        Set(VarSlot(pc.varname))
      case pr: PointR =>
        Set(VarSlot(pr.varname))
      case pla: Point with Loc with Arg =>
        Set(VarSlot(pla.argName))
      case pop: Point with Param =>
        Set(VarSlot(pop.paramName))
      case inp: Point with Invoke =>
        Set(InvokeSlot(inp.sig, inp.invokeTyp))
      case p: PointRet =>
        Set(VarSlot(p.retname))
      case _: PointMethodRet =>
        Set(VarSlot("ret"))
      case _ => throw new RuntimeException("No slot for such pta node: " + point + "@" + context)
    }
  }
}