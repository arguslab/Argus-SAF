/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.dda

import org.argus.jawa.flow._
import org.argus.jawa.flow.cfg._
import org.argus.jawa.flow.interprocedural.Callee
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
trait DataDependenceBaseGraph[Node <: IDDGNode]
    extends AlirGraphImpl[Node]
    with AlirSuccPredAccesses[Node]
    with AlirEdgeAccesses[Node] {

  def entryNode: Node
  def icfg: InterProceduralControlFlowGraph[ICFGNode]

  def findDefSite(defSite: Context, isRet: Boolean = false): Option[Node] = {
    if(this.icfg.icfgNormalNodeExists(defSite)) {
      val node = this.icfg.getICFGNormalNode(defSite).asInstanceOf[ICFGNormalNode]
      if(iddgNormalNodeExists(node)) {
        return Some(getIDDGNormalNode(node))
      }
    }
    if(isRet && this.icfg.icfgReturnNodeExists(defSite)) {
      val node = this.icfg.getICFGReturnNode(defSite).asInstanceOf[ICFGReturnNode]
      if(iddgReturnVarNodeExists(node)) {
        return Some(getIDDGReturnVarNode(node))
      }
    }
    if(this.icfg.icfgCallNodeExists(defSite)) {
      val node = this.icfg.getICFGCallNode(defSite).asInstanceOf[ICFGCallNode]
      if(iddgVirtualBodyNodeExists(node)) {
        return Some(getIDDGVirtualBodyNode(node))
      }
    }
    if(defSite.getLocUri.startsWith("Entry:")) {
      val context = defSite.copy.removeTopContext()
      context.setContext(defSite.getMethodSig, "Entry")
      if(this.icfg.icfgEntryNodeExists(context)) {
        val node = this.icfg.getICFGEntryNode(context).asInstanceOf[ICFGEntryNode]
        val pos = defSite.getLocUri.split("\\.")(1).toInt
        return Some(getIDDGEntryParamNode(node, pos))
      }
    }
    if(defSite.getLocUri == "L0000") {
      return Some(this.entryNode)
    }
    None
  }

  def findVirtualBodyDefSite(defSite: Context): Option[Node] = {
    val icfgN = if(this.icfg.icfgCallNodeExists(defSite)) Some(this.icfg.getICFGCallNode(defSite)) else None
    icfgN match {
      case Some(n: ICFGCallNode) =>
        if(iddgVirtualBodyNodeExists(n)) 
          Some(getIDDGVirtualBodyNode(n))
        else None
      case _ => None
    }
  }

  def findDefSite(defSite: Context, position: Int): Node = {
    val icfgN = {
      if(this.icfg.icfgCallNodeExists(defSite)) this.icfg.getICFGCallNode(defSite)
      else if(this.icfg.icfgReturnNodeExists(defSite)) this.icfg.getICFGReturnNode(defSite)
      else if(this.icfg.icfgEntryNodeExists(defSite)) this.icfg.getICFGEntryNode(defSite)
      else if(this.icfg.icfgExitNodeExists(defSite)) this.icfg.getICFGExitNode(defSite)
      else throw new RuntimeException("Cannot find node: " + defSite)
    }
    icfgN match {
      case icfgN1: ICFGCallNode if iddgCallArgNodeExists(icfgN1, position) => getIDDGCallArgNode(icfgN1, position)
      case icfgN1: ICFGReturnNode if iddgReturnArgNodeExists(icfgN1, position) => getIDDGReturnArgNode(icfgN1, position)
      case icfgN1: ICFGEntryNode if iddgEntryParamNodeExists(icfgN1, position) => getIDDGEntryParamNode(icfgN1, position)
      case icfgN1: ICFGExitNode if iddgExitParamNodeExists(icfgN1, position) => getIDDGExitParamNode(icfgN1, position)
      case _ => throw new RuntimeException("Cannot find node: " + icfgN + ":" + position)
    }
  }

  def getNode(icfgNode: ICFGNode, pos: Option[Int]): Node = {
    icfgNode match {
      case en: ICFGEntryNode =>
        assert(pos.isDefined, "pos has to be set for getIDDGEntryParamNode.")
        getIDDGEntryParamNode(en, pos.get)
      case en: ICFGExitNode =>
        assert(pos.isDefined, "pos has to be set for getIDDGEntryParamNode.")
        getIDDGExitParamNode(en, pos.get)
      case cn: ICFGCenterNode =>
        getIDDGCenterNode(cn)
      case cn: ICFGCallNode =>
        pos match {
          case Some(position) => getIDDGCallArgNode(cn, position)
          case None => getIDDGVirtualBodyNode(cn)
        }
      case rn: ICFGReturnNode =>
        pos match {
          case Some(position) => getIDDGReturnArgNode(rn, position)
          case None => getIDDGReturnVarNode(rn)
        }
      case nn: ICFGNormalNode => getIDDGNormalNode(nn)
      case _ => throw new RuntimeException("Unexpected node type experienced: " + icfgNode)
    }
  }

  def iddgEntryParamNodeExists(icfgN: ICFGEntryNode, position: Int): Boolean = {
    graph.containsVertex(newIDDGEntryParamNode(icfgN, position).asInstanceOf[Node])
  }

  def addIDDGEntryParamNode(icfgN: ICFGEntryNode, position: Int): Node = {
    val node = newIDDGEntryParamNode(icfgN, position).asInstanceOf[Node]
    val n =
      if (pool.contains(node)) pool(node)
      else {
        pl += (node -> node)
        node
      }
    graph.addVertex(n)
    n
  }

  def getIDDGEntryParamNode(icfgN: ICFGEntryNode, position: Int): Node =
    pool(newIDDGEntryParamNode(icfgN, position))

  protected def newIDDGEntryParamNode(icfgN: ICFGEntryNode, position: Int) =
    IDDGEntryParamNode(icfgN, position)
  
  def iddgExitParamNodeExists(icfgN: ICFGExitNode, position: Int): Boolean = {
    graph.containsVertex(newIDDGExitParamNode(icfgN, position).asInstanceOf[Node])
  }

  def addIDDGExitParamNode(icfgN: ICFGExitNode, position: Int): Node = {
    val node = newIDDGExitParamNode(icfgN, position).asInstanceOf[Node]
    val n =
      if (pool.contains(node)) pool(node)
      else {
        pl += (node -> node)
        node
      }
    graph.addVertex(n)
    n
  }

  def getIDDGExitParamNode(icfgN: ICFGExitNode, position: Int): Node =
    pool(newIDDGExitParamNode(icfgN, position))

  protected def newIDDGExitParamNode(icfgN: ICFGExitNode, position: Int) =
    IDDGExitParamNode(icfgN, position)

  def iddgCallArgNodeExists(icfgN: ICFGCallNode, position: Int): Boolean = {
    graph.containsVertex(newIDDGCallArgNode(icfgN, position).asInstanceOf[Node])
  }

  def addIDDGCallArgNode(icfgN: ICFGCallNode, position: Int): Node = {
    val node = newIDDGCallArgNode(icfgN, position).asInstanceOf[Node]
    val n =
      if (pool.contains(node)) pool(node)
      else {
        pl += (node -> node)
        node
      }
    graph.addVertex(n)
    n
  }

  def getIDDGCallArgNode(icfgN: ICFGCallNode, position: Int): Node =
    pool(newIDDGCallArgNode(icfgN, position))

  def getIDDGCallArgNodes(icfgN: ICFGCallNode): IList[Node] = {
    val result: MList[Node] = mlistEmpty
    var position = if(icfgN.getCallType == "static") 1 else 0
    while(iddgCallArgNodeExists(icfgN, position)){
      result += pool(newIDDGCallArgNode(icfgN, position))
      position += 1
    }
    result.toList
  }

  protected def newIDDGCallArgNode(icfgN: ICFGCallNode, position: Int) = IDDGCallArgNode(icfgN, position)

  def iddgReturnArgNodeExists(icfgN: ICFGReturnNode, position: Int): Boolean = {
    graph.containsVertex(newIDDGReturnArgNode(icfgN, position).asInstanceOf[Node])
  }

  def addIDDGReturnArgNode(icfgN: ICFGReturnNode, position: Int): Node = {
    val node = newIDDGReturnArgNode(icfgN, position).asInstanceOf[Node]
    val n =
      if (pool.contains(node)) pool(node)
      else {
        pl += (node -> node)
        node
      }
    graph.addVertex(n)
    n
  }

  def getIDDGReturnArgNode(icfgN: ICFGReturnNode, position: Int): Node =
    pool(newIDDGReturnArgNode(icfgN, position))

  protected def newIDDGReturnArgNode(icfgN: ICFGReturnNode, position: Int) = IDDGReturnArgNode(icfgN, position)

  def iddgReturnVarNodeExists(icfgN: ICFGReturnNode): Boolean = {
    graph.containsVertex(newIDDGReturnVarNode(icfgN).asInstanceOf[Node])
  }

  def addIDDGReturnVarNode(icfgN: ICFGReturnNode): Node = {
    val node = newIDDGReturnVarNode(icfgN).asInstanceOf[Node]
    val n =
      if (pool.contains(node)) pool(node)
      else {
        pl += (node -> node)
        node
      }
    graph.addVertex(n)
    n
  }

  def getIDDGReturnVarNode(icfgN: ICFGReturnNode): Node =
    pool(newIDDGReturnVarNode(icfgN))
    
  protected def newIDDGReturnVarNode(icfgN: ICFGReturnNode) =
    IDDGReturnVarNode(icfgN)
    
  def iddgVirtualBodyNodeExists(icfgN: ICFGCallNode): Boolean = {
    graph.containsVertex(newIDDGVirtualBodyNode(icfgN).asInstanceOf[Node])
  }
  
  def addIDDGVirtualBodyNode(icfgN: ICFGCallNode): Node = {
    val node = newIDDGVirtualBodyNode(icfgN).asInstanceOf[Node]
    val n =
      if (pool.contains(node)) pool(node)
      else {
        pl += (node -> node)
        node
      }
    graph.addVertex(n)
    n
  }

  def getIDDGVirtualBodyNode(icfgN: ICFGCallNode): Node =
    pool(newIDDGVirtualBodyNode(icfgN))
    
  protected def newIDDGVirtualBodyNode(icfgN: ICFGCallNode) =
    IDDGVirtualBodyNode(icfgN)
    
  def iddgNormalNodeExists(icfgN: ICFGNormalNode): Boolean = {
    graph.containsVertex(newIDDGNormalNode(icfgN).asInstanceOf[Node])
  }
  
  def addIDDGNormalNode(icfgN: ICFGNormalNode): Node = {
    val node = newIDDGNormalNode(icfgN).asInstanceOf[Node]
    val n =
      if (pool.contains(node)) pool(node)
      else {
        pl += (node -> node)
        node
      }
    graph.addVertex(n)
    n
  }

  def getIDDGNormalNode(icfgN: ICFGNormalNode): Node =
    pool(newIDDGNormalNode(icfgN))
    
  protected def newIDDGNormalNode(icfgN: ICFGNormalNode) =
    IDDGNormalNode(icfgN)
    
  def iddgCenterNodeExists(icfgN: ICFGCenterNode): Boolean = {
    graph.containsVertex(newIDDGCenterNode(icfgN).asInstanceOf[Node])
  }
  
  def addIDDGCenterNode(icfgN: ICFGCenterNode): Node = {
    val node = newIDDGCenterNode(icfgN).asInstanceOf[Node]
    val n =
      if (pool.contains(node)) pool(node)
      else {
        pl += (node -> node)
        node
      }
    graph.addVertex(n)
    n
  }

  def getIDDGCenterNode(icfgN: ICFGCenterNode): Node =
    pool(newIDDGCenterNode(icfgN))
    
  protected def newIDDGCenterNode(icfgN: ICFGCenterNode) =
    IDDGCenterNode(icfgN)
    
  def iddgEntryNodeExists(icfgN: ICFGEntryNode): Boolean = {
    graph.containsVertex(newIDDGEntryNode(icfgN).asInstanceOf[Node])
  }
  
  def addIDDGEntryNode(icfgN: ICFGEntryNode): Node = {
    val node = newIDDGEntryNode(icfgN).asInstanceOf[Node]
    val n =
      if (pool.contains(node)) pool(node)
      else {
        pl += (node -> node)
        node
      }
    graph.addVertex(n)
    n
  }

  def getIDDGCenterNode(icfgN: ICFGEntryNode): Node =
    pool(newIDDGEntryNode(icfgN))
    
  protected def newIDDGEntryNode(icfgN: ICFGEntryNode) =
    IDDGEntryNode(icfgN)
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
sealed abstract class IDDGNode(icfgN: ICFGNode) extends InterProceduralNode(icfgN.getContext) {
  def getICFGNode: ICFGNode = icfgN
  override def getOwner: Signature = icfgN.getOwner
  def getPosition: Option[Int]
  override def getContext: Context = icfgN.getContext
  override def toString: ResourceUri = icfgN.toString
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
abstract class IDDGVirtualNode(icfgN: ICFGNode) extends IDDGNode(icfgN) {
  def getPosition: Option[Int] = None
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
abstract class IDDGLocNode(icfgN: ICFGLocNode) extends IDDGNode(icfgN) {
  def getLocUri: String = icfgN.locUri
  def getLocIndex: Int = icfgN.locIndex
  def getPosition: Option[Int] = None
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
abstract class IDDGInvokeNode(icfgN: ICFGInvokeNode) extends IDDGLocNode(icfgN) {
  def getCalleeSet: ISet[Callee] = icfgN.getCalleeSet
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class IDDGNormalNode(icfgN: ICFGNormalNode) extends IDDGLocNode(icfgN) 

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class IDDGEntryParamNode(icfgN: ICFGEntryNode, position: Int) extends IDDGVirtualNode(icfgN){
  var paramName: String = _
  def getVirtualLabel: String = "EntryParam:" + position
  override def getPosition: Option[Int] = Some(position)
  override def toString: String = icfgN.toString() + "p" + position
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class IDDGCenterNode(icfgN: ICFGCenterNode) extends IDDGVirtualNode(icfgN){
  def getVirtualLabel: String = "Center"
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class IDDGEntryNode(icfgN: ICFGEntryNode) extends IDDGVirtualNode(icfgN)

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class IDDGExitParamNode(icfgN: ICFGExitNode, position: Int) extends IDDGVirtualNode(icfgN){
  var paramName: String = _
  def getVirtualLabel: String = "ExitParam:" + position
  override def getPosition: Option[Int] = Some(position)
  override def toString: String = icfgN.toString() + "p" + position
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class IDDGVirtualBodyNode(icfgN: ICFGCallNode) extends IDDGInvokeNode(icfgN){
  var argNames: List[String] = _
  def getInvokeLabel: String = "VirtualBody"
  override def toString: String = getInvokeLabel + "@" + icfgN.context
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class IDDGCallArgNode(icfgN: ICFGCallNode, position: Int) extends IDDGInvokeNode(icfgN){
  var argName: String = _
  def getInvokeLabel: String = "CallArg:" + position
  override def getPosition: Option[Int] = Some(position)
  override def toString: String = icfgN.toString() + "p" + position
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class IDDGReturnArgNode(icfgN: ICFGReturnNode, position: Int) extends IDDGInvokeNode(icfgN){
  var argName: String = _
  def getInvokeLabel: String = "ReturnArg:" + position
  override def getPosition: Option[Int] = Some(position)
  override def toString: String = icfgN.toString() + "p" + position
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class IDDGReturnVarNode(icfgN: ICFGReturnNode) extends IDDGInvokeNode(icfgN){
  var retVarName: String = _
  def getInvokeLabel: String = "ReturnVar"
  override def toString: String = getInvokeLabel + "@" + icfgN.context
}
