/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.callGraph

import com.tinkerpop.blueprints.{Edge, Vertex}
import com.tinkerpop.blueprints.impls.tg.TinkerGraph
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.controlFlowGraph._
import org.argus.jawa.alir.interprocedural.Callee
import org.argus.jawa.core.{JawaType, Signature}
import org.sireum.util._

class CallGraph {
  /**
   * map from methods to it's callee methods
   * map from caller sig to callee sigs
   */
  private val callMap: MMap[Signature, MSet[Signature]] = mmapEmpty
  
  def addCall(from: Signature, to: Signature) = this.callMap.getOrElseUpdate(from, msetEmpty) += to
  def addCalls(from: Signature, to: ISet[Signature]) = this.callMap.getOrElseUpdate(from, msetEmpty) ++= to
  
  def getCallMap: IMap[Signature, ISet[Signature]] = this.callMap.map{case (k, vs) => k -> vs.toSet}.toMap

  def getReachableMethods(procs: ISet[Signature]): ISet[Signature] = {
    calculateReachableMethods(procs, isetEmpty) ++ procs
  }
  
  private def calculateReachableMethods(procs: ISet[Signature], processed: Set[Signature]): ISet[Signature] = {
    if(procs.isEmpty) Set()
    else
      procs.map{
        proc =>
          if(processed.contains(proc)){
            Set[Signature]()
          } else {
            val callees = this.callMap.getOrElse(proc, msetEmpty).toSet
            callees ++ calculateReachableMethods(callees, processed + proc)
          }
      }.reduce((s1, s2) => s1 ++ s2)
  }
  
  private def addNode(header: String, tg: TinkerGraph, node: CGNode): Vertex = {
    var v = tg.getVertex(node.hashCode())
    if(v == null){
      v = tg.addVertex(node.hashCode())
      v.setProperty("method", node.getMethodName)
      v.setProperty("class", node.getClassType.name)
      v.setProperty("returnType", node.getReturnType.name)
      for(i <- node.getParamTypes.indices){
        v.setProperty("param" + i + "Type", node.getParamTypes(i))
      }
      v.setProperty("type", node.getType)
      v.setProperty("location", node.getLocation)
      if(header != null && !header.isEmpty)
        v.setProperty("header", header)
    }
    v
  }
  
  private def addEdge(header: String, tg: TinkerGraph, source: Vertex, target: Vertex, typ: String): Edge = {
    var e = tg.getEdge((source, target).hashCode())
    if(e == null){
      e = tg.addEdge((source, target).hashCode(), source, target, typ)
      if(header != null && !header.isEmpty)
        e.setProperty("header", header)
    }
    e
  }
  
  def toSimpleCallGraph(header: String, outpath: String, format: String) = {
    val fm = format match {
      case "GraphML" => TinkerGraph.FileType.GRAPHML
      case "GML" => TinkerGraph.FileType.GML
      case _ => throw new RuntimeException("Given format " + format + " does not supported!")
    }
    val scg = new TinkerGraph(outpath, fm)
    
    this.callMap.foreach {
      case (caller, callees) =>
        val callerContext = new Context
        callerContext.setContext(caller, caller.signature)
        val callerNode = CGSimpleCallNode(callerContext)
        val callerV = addNode(header, scg, callerNode)
        callees foreach {
          case callee =>
            val calleeContext = new Context
            calleeContext.setContext(callee, callee.signature)
            val calleeNode = CGSimpleCallNode(calleeContext)
            val calleeV = addNode(header, scg, calleeNode)
            addEdge(header, scg, callerV, calleeV, "calls")
        }
    }
    scg.shutdown()
  }
  
  def toDetailedCallGraph(header: String, icfg: InterproceduralControlFlowGraph[ICFGNode], outpath: String, format: String) = {
    val fm = format match {
      case "GraphML" => TinkerGraph.FileType.GRAPHML
      case "GML" => TinkerGraph.FileType.GML
      case _ => throw new RuntimeException("Given format " + format + " does not supported!")
    }
    val worklist: MList[ICFGNode] = mlistEmpty ++ icfg.nodes.toList
    while(worklist.nonEmpty) {
      val n = worklist.remove(0)
      n match{
        case cn: ICFGCallNode =>
          val rn = icfg.getICFGReturnNode(cn.context)
          icfg.addEdge(n, rn)
          icfg.predecessors(rn) foreach {
            pred =>
              if(pred.isInstanceOf[ICFGExitNode]){
                icfg.deleteEdge(pred, rn)
              }
          }
          val calleeSigs = cn.getCalleeSet.map(_.callee)
          val hasCallees = icfg.successors(cn).filter { x => x.isInstanceOf[ICFGEntryNode] }.map {
            succ =>
              succ.asInstanceOf[ICFGEntryNode].getOwner
          }
          (calleeSigs -- hasCallees).foreach {
            sig =>
              val calleeContext = cn.getContext.copy.setContext(sig, "Entry")
              val calleeEntryNode = icfg.addICFGEntryNode(calleeContext)
              icfg.addEdge(cn, calleeEntryNode)
          }
        case _ =>
      }
    }
    val ns = icfg.nodes filter{
      n =>
        n match{
          case cn: ICFGCallNode => false
          case en: ICFGEntryNode => false
          case en: ICFGExitNode => false
          case _ => true
        }
    }
    ns foreach icfg.compressByDelNode
    val dcg = new TinkerGraph(outpath, fm)
    icfg.nodes foreach {
      case cn: ICFGCallNode =>
        val callees: ISet[Callee] = cn.getCalleeSet
        val calleesig: Signature = cn.getCalleeSig
        val source = CGDetailCallNode(calleesig, callees, cn.context)
        val sourceV = addNode(header, dcg, source)
        icfg.successors(cn).foreach {
          case sen: ICFGEntryNode =>
            val target = CGEntryNode(sen.context)
            val targetV = addNode(header, dcg, target)
            addEdge(header, dcg, sourceV, targetV, "calls")
          case sen: ICFGExitNode =>
            val target = CGExitNode(sen.context)
            val targetV = addNode(header, dcg, target)
            addEdge(header, dcg, sourceV, targetV, "leadsto")
          case scn: ICFGCallNode =>
            val callees: ISet[Callee] = scn.getCalleeSet
            val calleesig: Signature = scn.getCalleeSig
            val target = CGDetailCallNode(calleesig, callees, scn.context)
            val targetV = addNode(header, dcg, target)
            addEdge(header, dcg, sourceV, targetV, "leadsto")
          case s => throw new RuntimeException(s + " cannot be successor of " + cn + "!")
        }

      case en: ICFGEntryNode =>
        val source = CGEntryNode(en.context)
        val sourceV = addNode(header, dcg, source)
        icfg.successors(en) foreach {
          case s =>
            s match {
              case sen: ICFGExitNode =>
                val target = CGExitNode(sen.context)
                val targetV = addNode(header, dcg, target)
                addEdge(header, dcg, sourceV, targetV, "leadsto")
              case scn: ICFGCallNode =>
                val callees: ISet[Callee] = scn.getCalleeSet
                val calleesig: Signature = scn.getCalleeSig
                val target = CGDetailCallNode(calleesig, callees, scn.context)
                val targetV = addNode(header, dcg, target)
                addEdge(header, dcg, sourceV, targetV, "leadsto")
              case _ => throw new RuntimeException(s + " cannot be successor of " + en + "!")
            }
        }
      case en: ICFGExitNode =>
        val source = CGExitNode(en.context)
        val sourceV = addNode(header, dcg, source)
        icfg.successors(en) foreach {
          case s => // s should be only IcfgCallNode
            s match {
              case cn: ICFGCallNode =>
                val callees: ISet[Callee] = cn.getCalleeSet
                val calleesig: Signature = cn.getCalleeSig
                val target = CGDetailCallNode(calleesig, callees, cn.context)
                val targetV = addNode(header, dcg, target)
                addEdge(header, dcg, sourceV, targetV, "return")
              case _ => throw new RuntimeException(s + " cannot be successor of " + en + "!")
            }

        }
      case n => throw new RuntimeException(n + " should not exist!")
    }
    dcg.shutdown()
  }
}

sealed abstract class CGNode(context: Context) {
  def getID: String = this.hashCode().toLong.toString
  def getMethodName: String = context.getMethodSig.methodName
  def getClassType: JawaType = context.getMethodSig.getClassType
  def getReturnType: JawaType = context.getMethodSig.getReturnType
  def getParamTypes: ISeq[JawaType] = context.getMethodSig.getParameterTypes
  def getType: String
  def getLocation: String = context.getCurrentLocUri
}

abstract class CGVirtualNode(context: Context) extends CGNode(context){
  override def toString: String = getID + ":" + getType
}

final case class CGEntryNode(context: Context) extends CGVirtualNode(context){
  def getType: String = "Entry"
}

final case class CGExitNode(context: Context) extends CGVirtualNode(context){
  def getType: String = "Exit"  
}

abstract class CGCallNode(context: Context) extends CGNode(context) {
  def getType: String = "Call"
}

final case class CGSimpleCallNode(context: Context) extends CGCallNode(context){
  override def toString: String = getID
}

final case class CGDetailCallNode(sig: Signature, callees: ISet[Callee], context: Context) extends CGCallNode(context){
  override def getMethodName: String = sig.methodName
  override def getClassType: JawaType = sig.getClassType
  override def getReturnType: JawaType = sig.getReturnType
  override def getParamTypes: ISeq[JawaType] = sig.getParameterTypes
  override def toString: String = getID + ":" + getType + "@" + getLocation
}
