/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.interactive

import java.util.concurrent.ConcurrentLinkedQueue

import org.argus.jawa.core.ast.CompilationUnit
import org.argus.jawa.core.io.{AbstractFile, Problem}
import org.argus.jawa.core.util._
import scala.collection.JavaConverters._

trait RichCompilationUnits { self: Global =>
  private val unitOfFile: MMap[AbstractFile, RichCompilationUnit] = cmapEmpty
  
  /** A set containing all those files that need to be removed
   *  Units are removed by getUnit, typically once a unit is finished compiled.
   */
  protected val toBeRemoved: ConcurrentLinkedQueue[AbstractFile] = new ConcurrentLinkedQueue[AbstractFile]()

  /** A set containing all those files that need to be removed after a full background compiler run
   */
  protected val toBeRemovedAfterRun: ConcurrentLinkedQueue[AbstractFile] = new ConcurrentLinkedQueue[AbstractFile]()
  
  def addCompilationUnit(file: AbstractFile, rcu: RichCompilationUnit): Option[RichCompilationUnit] = this.unitOfFile.put(file, rcu)
  def addCompilationUnits(rcus: ISeq[RichCompilationUnit]): Unit = {
    rcus.foreach(rcu => addCompilationUnit(rcu.cu.pos.source.file, rcu))
  }
  def removeCompilationUnit(file: AbstractFile): Option[RichCompilationUnit] = this.unitOfFile.remove(file)
  def getCompilationUnits: IMap[AbstractFile, RichCompilationUnit] = this.unitOfFile.toMap
  def getCompilationUnit(file: AbstractFile): Option[RichCompilationUnit] ={
    toBeRemoved.asScala.foreach { t =>
      informIDE("removed: " + t)
      unitOfFile -= t
    }
    toBeRemoved.clear()
    this.unitOfFile.get(file)
  }
  def hasCompilationUnit(file: AbstractFile): Boolean = this.unitOfFile.contains(file)
  def managedFiles: ISet[AbstractFile] = this.unitOfFile.keySet.toSet
  
  case class RichCompilationUnit(cu: CompilationUnit) {
    /** The problems reported for this unit */
    val problems: MList[Problem] = mlistEmpty
  }
}