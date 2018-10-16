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

import org.argus.jawa.flow.cfg.{ControlFlowGraph, IntraProceduralControlFlowGraph}
import org.argus.jawa.flow.rda._
import org.argus.jawa.core._
import org.argus.jawa.core.util._

object EdgeType extends Enumeration {
  val ALLOCATION, ASSIGNMENT, FIELD_STORE, FIELD_LOAD, ARRAY_STORE, ARRAY_LOAD, STATIC_FIELD_STORE, STATIC_FIELD_LOAD, TRANSFER, THIS_TRANSFER = Value
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
trait PAGConstraint{
  
  def applyConstraint(
      p: Point,
      ps: Set[Point],
      cfg: IntraProceduralControlFlowGraph[ControlFlowGraph.Node],
      rda: ReachingDefinitionAnalysis.Result): MMap[EdgeType.Value, MMap[Point, MSet[Point]]] = {
    //contains the edge list related to point p
    val flowMap: MMap[EdgeType.Value, MMap[Point, MSet[Point]]] = mmapEmpty
    p match {
      case asmtP: PointAsmt =>
        val lhs = asmtP.lhs
        val rhs = asmtP.rhs
        lhs match {
          case pfl: PointFieldL =>
            flowMap.getOrElseUpdate(EdgeType.FIELD_STORE, mmapEmpty).getOrElseUpdate(rhs, msetEmpty) += pfl
            udChain(pfl.baseP, ps, cfg, rda).foreach { point =>
              flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(point, msetEmpty) += pfl.baseP
            }
            rhs match {
              case pr: PointR =>
                udChain(pr, ps, cfg, rda).foreach { point =>
                  flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(point, msetEmpty) += pr
                }
              case _ =>
            }
          //if an array point in lhs, then have flow from this array point to most recent array var shadowing place
          case pal: PointMyArrayL =>
            flowMap.getOrElseUpdate(EdgeType.ARRAY_STORE, mmapEmpty).getOrElseUpdate(rhs, msetEmpty) += pal
            udChain(pal, ps, cfg, rda).foreach { point =>
              flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(point, msetEmpty) += pal
            }
            rhs match {
              case pr: PointR =>
                udChain(pr, ps, cfg, rda).foreach { point =>
                  flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(point, msetEmpty) += pr
                }
              case _ =>
            }
          case pgl: PointStaticFieldL =>
            flowMap.getOrElseUpdate(EdgeType.STATIC_FIELD_STORE, mmapEmpty).getOrElseUpdate(rhs, msetEmpty) += pgl
            rhs match {
              case pr: PointR =>
                udChain(pr, ps, cfg, rda).foreach { point =>
                  flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(point, msetEmpty) += pr
                }
              case _ =>
            }
          case _ =>
            rhs match {
              case pfr: PointFieldR =>
                flowMap.getOrElseUpdate(EdgeType.FIELD_LOAD, mmapEmpty).getOrElseUpdate(pfr, msetEmpty) += lhs
                udChain(pfr.baseP, ps, cfg, rda).foreach { point =>
                  flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(point, msetEmpty) += pfr.baseP
                }
              case par: PointMyArrayR =>
                flowMap.getOrElseUpdate(EdgeType.ARRAY_LOAD, mmapEmpty).getOrElseUpdate(par, msetEmpty) += lhs
                udChain(par, ps, cfg, rda).foreach { point =>
                  flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(point, msetEmpty) += par
                }
              case pgr: PointStaticFieldR =>
                flowMap.getOrElseUpdate(EdgeType.STATIC_FIELD_LOAD, mmapEmpty).getOrElseUpdate(pgr, msetEmpty) += lhs
              case _: PointExceptionR =>
                flowMap.getOrElseUpdate(EdgeType.ALLOCATION, mmapEmpty).getOrElseUpdate(rhs, msetEmpty) += lhs
              case _: Point with Right with NewObj =>
                flowMap.getOrElseUpdate(EdgeType.ALLOCATION, mmapEmpty).getOrElseUpdate(rhs, msetEmpty) += lhs
              case pr: Point with Loc with Right =>
                flowMap.getOrElseUpdate(EdgeType.ASSIGNMENT, mmapEmpty).getOrElseUpdate(pr, msetEmpty) += lhs
                udChain(pr, ps, cfg, rda).foreach { point =>
                  flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(point, msetEmpty) += pr
                }
            }
        }
      case pc: PointCall =>
        val lhsOpt = pc.lhsOpt
        val rhs = pc.rhs
        lhsOpt foreach{ lhs =>
          flowMap.getOrElseUpdate(EdgeType.ASSIGNMENT, mmapEmpty).getOrElseUpdate(rhs, msetEmpty) += lhs
        }
        rhs match {
          case psi: PointStaticI =>
            psi.argPsCall.foreach{
              case (i, cp) =>
                udChain(cp, ps, cfg, rda).foreach { point =>
                  flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(point, msetEmpty) += cp
                }
                flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(cp, msetEmpty) += psi.argPsReturn(i)
            }
          case pi: PointI =>
            udChain(pi.recvPCall, ps, cfg, rda).foreach { point =>
              flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(point, msetEmpty) += pi.recvPCall
            }
            flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(pi.recvPCall, msetEmpty) += pi.recvPReturn
            pi.argPsCall.foreach{
              case (i, cp) => 
                udChain(cp, ps, cfg, rda).foreach { point =>
                  flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(point, msetEmpty) += cp
                }
                flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(cp, msetEmpty) += pi.argPsReturn(i)
            }
        }
      case procP: PointMethod =>
        val t_exit = procP.thisPExit
        val ps_exit = procP.paramPsExit
        udChainForMethodExit(t_exit, ps, cfg, rda).foreach{ point =>
          flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(point, msetEmpty) += t_exit
        }
        ps_exit.foreach{
          case (_, p_exit) =>
            udChainForMethodExit(p_exit, ps, cfg, rda).foreach{ point =>
              flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(point, msetEmpty) += p_exit
            }
        }
      case retP: PointRet =>
        udChain(retP, ps, cfg, rda).foreach { point =>
          flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(point, msetEmpty) += retP
        }
        retP.procPoint.retVar match{
          case Some(rev) =>
            flowMap.getOrElseUpdate(EdgeType.TRANSFER, mmapEmpty).getOrElseUpdate(retP, msetEmpty) += rev
          case None =>
        }
        
      case _ =>
    }
    flowMap
  }
  
  def udChainForMethodExit(
      p: Point with Param with Exit,
      points: Set[Point],
      cfg: IntraProceduralControlFlowGraph[ControlFlowGraph.Node],
      rda: ReachingDefinitionAnalysis.Result,
      avoidMode: Boolean = true): Set[Point] = {
    val slots = rda.entrySet(cfg.exitNode)
    searchRda(p, points, slots, avoidMode)
  }
  
//  def untilFindUdChain(p: PointWithIndex,
//              points: MList[Point],
//              cfg: ControlFlowGraph[String],
//              rda: ReachingDefinitionAnalysis.Result,
//              avoidMode: Boolean = true): Set[Point] = {
//    val slots = rda.entrySet(cfg.getNode(Some(p.locationUri), p.locationIndex))
//    searchRdaUntilFind(p, slots, cfg, rda, mlistEmpty, avoidMode)
//  }
  
  def udChain(
      p: Point with Loc,
      points: Set[Point],
      cfg: IntraProceduralControlFlowGraph[ControlFlowGraph.Node],
      rda: ReachingDefinitionAnalysis.Result,
      avoidMode: Boolean = true): Set[Point] = {
    val slots = rda.entrySet(cfg.getNode(p.locUri, p.locIndex))
    searchRda(p, points, slots, avoidMode)
  }
  
  def searchRda(p: Point, points: Set[Point], slots: ISet[(Slot, DefDesc)], avoidMode: Boolean): Set[Point] = {
    var ps: Set[Point] = Set()
    slots.foreach{
      case (slot, defDesc) => 
        val varName =
          p match {
            case pl: PointL => pl.varname
            case pr: PointR => pr.varname
            case pc: PointCastR => pc.varname
            case pr: PointRet => pr.retname
            case gl: Point with Static_Field => gl.staticFieldFQN.toString()
            case ba: Point with Base => ba.baseName
            case al: PointMyArrayL => al.arrayname
            case ar: PointMyArrayR => ar.arrayname
            case pa: Point with Arg => pa.argName
            case pp: Point with Param => pp.paramName
            case _ => ""
          }
        if(varName.equals(slot.toString)){
          if(defDesc.toString.equals("*")) {
            if(!varName.startsWith("@@")) {
              val tp = getPointFromEntry(varName, points, avoidMode)
              if(tp!=null)
                ps += tp
            }
          } else {
            defDesc match {
              case pdd: ParamDefDesc =>
                val tp = getParamPoint_Return(varName, pdd.paramIndex, pdd.locUri, pdd.locIndex, points, avoidMode)
                if(tp != null)
                  ps += tp
              case ldd: LocDefDesc => 
                val tp = getPoint(varName, ldd.locUri, ldd.locIndex, points, avoidMode)
                if(tp != null)
                  ps += tp
              case _ =>
            }
          }
        }
    }
    ps
  }
  
  private def getPoint(uri: ResourceUri, locUri: ResourceUri, locIndex: Int, ps: Set[Point], avoidMode: Boolean): Point = {
    var point: Point = null
    ps.foreach {
      case callP: PointCall =>
        callP.lhsOpt match {
          case Some(lhs) =>
            lhs match {
              case iP: PointL =>
                val locationUri = iP.locUri
                val locationIndex = iP.locIndex
                if (iP.varname.equals(uri) && locUri.equals(locationUri) && locIndex == locationIndex)
                  point = lhs
              case _ =>
            }
          case _ =>
        }
      case asmtP: PointAsmt =>
        val lhs = asmtP.lhs
        lhs match {
          case flP: PointFieldL =>
            val baseP = flP.baseP
            val locationUri = baseP.locUri
            val locationIndex = baseP.locIndex
            if (baseP.baseName.equals(uri) && locUri.equals(locationUri) && locIndex == locationIndex)
              point = baseP
          case gl: Point with Loc with Static_Field with Left =>
            if (gl.staticFieldFQN.toString().equals(uri) && locUri.equals(gl.locUri) && locIndex == gl.locIndex)
              point = lhs
          case ar: PointMyArrayL =>
            if (ar.arrayname.equals(uri) && locUri.equals(ar.locUri) && locIndex == ar.locIndex)
              point = lhs
          case iP: PointL =>
            val locationUri = iP.locUri
            val locationIndex = iP.locIndex
            if (iP.varname.equals(uri) && locUri.equals(locationUri) && locIndex == locationIndex)
              point = lhs
          case _ =>
        }
      case _ =>
    }
    if(!avoidMode)
      require(point != null)
    point
  }
  
  private def getParamPoint_Return(uri: ResourceUri, paramIndex: Int, locUri: ResourceUri, locIndex: Int, ps: Set[Point], avoidMode: Boolean): Point = {
    var point: Point = null
    ps.foreach {
      case pc: PointCall =>
        pc.rhs match {
          case psi: PointStaticI =>
            val candidateP = psi.argPsReturn.get(paramIndex)
            if (candidateP.isDefined && candidateP.get.argName == uri && candidateP.get.locUri == locUri && candidateP.get.locIndex == locIndex) point = candidateP.get
          case pi: PointI =>
            val candidateP =
              if (paramIndex == 0) Some(pi.recvPReturn)
              else pi.argPsReturn.get(paramIndex)
            if (candidateP.isDefined && candidateP.get.argName == uri && candidateP.get.locUri == locUri && candidateP.get.locIndex == locIndex) point = candidateP.get
        }
      case _ =>
    }
    if(!avoidMode)
      require(point != null)
    point
  }
  
  private def getPointFromEntry(uri: ResourceUri, ps: Set[Point], avoidMode: Boolean): Point = {
    var point: Point = null
    ps.foreach {
      case psp: PointStaticMethod =>
        psp.paramPsEntry.foreach {
          case (_, pa) =>
            if (pa.paramName.equals(uri)) {
              point = pa
            }
        }
      case pp: PointMethod =>
        if (pp.thisPEntry.paramName.equals(uri)) {
          point = pp.thisPEntry
        }
        pp.paramPsEntry.foreach {
          case (_, pa) =>
            if (pa.paramName.equals(uri)) {
              point = pa
            }
        }
      case _ =>
    }
    if(!avoidMode) {
      require(point != null)
    }
    point
  }
}
