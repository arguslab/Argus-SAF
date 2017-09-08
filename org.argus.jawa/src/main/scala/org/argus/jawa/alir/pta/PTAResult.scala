/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta

import org.argus.jawa.alir.Context
import org.argus.jawa.core.util._

object PTAResult {
  type PTSMap = IMap[PTASlot, ISet[Instance]]
}

class PTAResult {
  import PTAResult._
  
  private val ptMap: MMap[Context, MMap[PTASlot, MSet[Instance]]] = mmapEmpty

  def pointsToMap: IMap[Context, PTSMap] = {
    ptMap.map{
      case (c, m) =>
        (c, m.map{
          case (str, s) =>
            (str, s.toSet)
        }.toMap)
    }.toMap
  }
  
  def addPointsToMap(ptMap: IMap[Context, PTSMap]): Unit = {
    ptMap.foreach {
      case (c, m) =>
        m.foreach {
          case (str, s) =>
            addInstances(c, str, s)
        }
    }
  }
  
  def merge(result: PTAResult): PTAResult = {
    addPointsToMap(result.pointsToMap)
    this
  }
  
  def setInstance(context: Context, s: PTASlot, i: Instance): Unit = {
    ptMap(context)(s) = msetEmpty + i
  }
  def setInstances(context: Context, s: PTASlot, is: ISet[Instance]): Unit = {
    ptMap(context)(s) = msetEmpty ++ is
  }
  def addSlot(context: Context, s: PTASlot): Unit = ptMap.getOrElseUpdate(context, mmapEmpty).getOrElseUpdate(s, msetEmpty)
  def addInstance(context: Context, s: PTASlot, i: Instance): Unit = ptMap.getOrElseUpdate(context, mmapEmpty).getOrElseUpdate(s, msetEmpty) += i
  def addInstances(context: Context, s: PTASlot, is: ISet[Instance]): Unit = ptMap.getOrElseUpdate(context, mmapEmpty).getOrElseUpdate(s, msetEmpty) ++= is
  def updateSlotIfPresent(context: Context, s: PTASlot, i: Instance): Boolean = {
    ptMap.get(context) match {
      case Some(map) =>
        map.get(s) match {
          case Some(inss) =>
            inss += i
            true
          case None => false
        }
      case None => false
    }
  }
  def removeInstance(context: Context, s: PTASlot, i: Instance): Unit =
    ptMap.getOrElseUpdate(context, mmapEmpty).getOrElseUpdate(s, msetEmpty) -= i
  def removeInstances(context: Context, s: PTASlot, is: ISet[Instance]): Unit =
    ptMap.getOrElseUpdate(context, mmapEmpty).getOrElseUpdate(s, msetEmpty) --= is
  def pointsToSet(context: Context, s: PTASlot): ISet[Instance] =
    ptMap.getOrElse(context, mmapEmpty).getOrElse(s, msetEmpty).toSet
  def getPTSMap(context: Context): PTSMap = {
    ptMap.getOrElseUpdate(context, mmapEmpty).map{
      case (str, s) =>
        (str, s.toSet)
    }.toMap
  }

  def getRelatedInstances(context: Context, s: PTASlot): ISet[Instance] = {
    val bValue = pointsToSet(context, s)
    val rhValue = getRelatedHeapInstances(context, bValue)
    bValue ++ rhValue
  }

  def getRelatedHeapInstances(context: Context, insts: ISet[Instance]): ISet[Instance] = {
    val processed: MSet[Instance] = msetEmpty
    var result: ISet[Instance] = isetEmpty
    val worklistAlgorithm = new WorklistAlgorithm[Instance] {
      override def processElement(ins: Instance): Unit = {
        processed += ins
        val hMap = getPTSMap(context).filter{case (s, _) => s.isInstanceOf[HeapSlot] && s.asInstanceOf[HeapSlot].matchWithInstance(ins)}
        val hInss = hMap.flatMap(_._2).toSet
        result ++= hInss
        worklist ++= hInss.diff(processed)
      }
    }
    worklistAlgorithm.run(worklistAlgorithm.worklist ++= insts)
    result
  }

  def getRelatedInstancesMap(context: Context, s: PTASlot): IMap[PTASlot, ISet[Instance]] = {
    val bValue = pointsToSet(context, s)
    val bMap: IMap[PTASlot, ISet[Instance]] = Map(s -> bValue)
    val rMap: IMap[PTASlot, ISet[Instance]] = getRelatedHeapInstancesMap(context, bValue)
    bMap ++ rMap
  }

  def getRelatedHeapInstancesMap(context: Context, insts: ISet[Instance]): IMap[PTASlot, ISet[Instance]] = {
    val processed: MSet[Instance] = msetEmpty
    var result: IMap[PTASlot, ISet[Instance]] = imapEmpty
    val worklistAlgorithm = new WorklistAlgorithm[Instance] {
      override def processElement(ins: Instance): Unit = {
        processed += ins
        val hMap = getPTSMap(context).filter{case (s, _) => s.isInstanceOf[HeapSlot] && s.asInstanceOf[HeapSlot].matchWithInstance(ins)}
        result ++= hMap
        worklist ++= hMap.flatMap(_._2).toSet.diff(processed)
      }
    }
    worklistAlgorithm.run(worklistAlgorithm.worklist ++= insts)
    result
  }

  def pprint(): Unit = {
    ptMap.toList.sortBy(_._1.getCurrentLocUri).foreach {
      case (c, map) =>
        println(c.getCurrentLocUri + ":")
        map.foreach {
          case (s, inss) =>
            println("  " + s + "---" + inss.mkString(", "))
        }
    }
  }
}
