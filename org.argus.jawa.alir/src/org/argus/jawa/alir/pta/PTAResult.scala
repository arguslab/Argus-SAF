/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta

import org.argus.jawa.alir.Context
import org.argus.jawa.core.Signature
import org.sireum.util._

object PTAResult {
  type PTSMap = IMap[PTASlot, ISet[Instance]]
}

class PTAResult {
  import PTAResult._
  
  private val entryPoints: MSet[Signature] = msetEmpty
  
  def addEntryPoint(ep: Signature) = this.entryPoints += ep
  def addEntryPoints(eps: ISet[Signature]) = this.entryPoints ++= eps
  def getEntryPoints: ISet[Signature] = this.entryPoints.toSet
  
  private val ptMap: MMap[String, MMap[PTASlot, MSet[Instance]]] = mmapEmpty
  def pointsToMap: IMap[String, PTSMap] = {
    ptMap.map{
      case (c, m) =>
        (c, m.map{
          case (str, s) =>
            (str, s.toSet)
        }.toMap)
    }.toMap
  }
  
  def addPointsToMap(ptMap: IMap[String, PTSMap]) = {
    ptMap.foreach {
      case (c, m) =>
        m.foreach {
          case (str, s) =>
            addInstances(str, c, s)
        }
    }
  }
  
  def merge(result: PTAResult): PTAResult = {
    addEntryPoints(result.getEntryPoints)
    addPointsToMap(result.pointsToMap)
    this
  }
  
  def setInstance(s: PTASlot, context: String, i: Instance) = {
    ptMap.getOrElseUpdate(context, mmapEmpty).getOrElseUpdate(s, msetEmpty).clear()
    ptMap(context)(s) += i
  }
  def setInstances(s: PTASlot, context: String, is: ISet[Instance]): Unit = {
    ptMap.getOrElseUpdate(context, mmapEmpty).getOrElseUpdate(s, msetEmpty).clear()
    ptMap(context)(s) ++= is
  }
  def setInstances(s: PTASlot, context: Context, is: ISet[Instance]): Unit = {
    setInstances(s, context.toFullString, is)
  }
  def addInstance(s: PTASlot, context: String, i: Instance): Unit = ptMap.getOrElseUpdate(context, mmapEmpty).getOrElseUpdate(s, msetEmpty) += i
  def addInstances(s: PTASlot, context: String, is: ISet[Instance]): Unit = ptMap.getOrElseUpdate(context, mmapEmpty).getOrElseUpdate(s, msetEmpty) ++= is
  def addInstance(s: PTASlot, context: Context, i: Instance): Unit = addInstance(s, context.toFullString, i)
  def addInstances(s: PTASlot, context: Context, is: ISet[Instance]): Unit = addInstances(s, context.toFullString, is)
  def removeInstance(s: PTASlot, context: String, i: Instance): Unit = {
    ptMap.getOrElseUpdate(context, mmapEmpty).getOrElseUpdate(s, msetEmpty) -= i
  }
  def removeInstances(s: PTASlot, context: String, is: ISet[Instance]): Unit = ptMap.getOrElseUpdate(context, mmapEmpty).getOrElseUpdate(s, msetEmpty) --= is
  def removeInstance(s: PTASlot, context: Context, i: Instance): Unit = {
    removeInstance(s, context.toFullString, i)
  }
  def removeInstances(s: PTASlot, context: Context, is: ISet[Instance]): Unit = removeInstances(s, context.toFullString, is)
  
  def pointsToSet(s: PTASlot, context: String): ISet[Instance] = {
    ptMap.getOrElse(context, mmapEmpty).getOrElse(s, msetEmpty).toSet
  }
  def pointsToSet(s: PTASlot, context: Context): ISet[Instance] = {
    ptMap.getOrElse(context.toFullString, mmapEmpty).getOrElse(s, msetEmpty).toSet
  }
  def getPTSMap(context: String): PTSMap = {
    ptMap.getOrElseUpdate(context, mmapEmpty).map{
      case (str, s) =>
        (str, s.toSet)
    }.toMap
  }
  def getPTSMap(context: Context): PTSMap = {
    getPTSMap(context.toFullString)
  }
  def getRelatedInstances(s: PTASlot, context: Context): ISet[Instance] = {
    getRelatedInstances(s, context.toFullString)
  }
  
  def getRelatedInstances(s: PTASlot, context: String): ISet[Instance] = {
    val bValue = pointsToSet(s, context)
    val rhValue = getRelatedHeapInstances(bValue, context)
    bValue ++ rhValue
  }
  def getRelatedHeapInstances(insts: ISet[Instance], context: Context): ISet[Instance] = {
    getRelatedHeapInstances(insts, context.toFullString)
  }
  def getRelatedHeapInstances(insts: ISet[Instance], context: String): ISet[Instance] = {
    val worklist: MList[Instance] = mlistEmpty ++ insts
    val processed: MSet[Instance] = msetEmpty
    val result: MSet[Instance] = msetEmpty
    while(worklist.nonEmpty){
      val ins = worklist.remove(0)
      processed += ins
      val hMap = getPTSMap(context).filter{case (s, _) => s.isInstanceOf[HeapSlot] && s.asInstanceOf[HeapSlot].matchWithInstance(ins)}
      val hInss = hMap.flatMap(_._2).toSet
      result ++= hInss
      worklist ++= hInss.diff(processed)
    }
    result.toSet
  }
}
