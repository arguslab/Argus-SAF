/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.compiler.interactive

import org.argus.jawa.compiler.parser.CompilationUnit
import org.argus.jawa.core.Problem
import org.argus.jawa.core.io.AbstractFile
import org.sireum.util._

import scala.collection.mutable

trait RichCompilationUnits { self: Global =>
  private val unitOfFile = new mutable.LinkedHashMap[AbstractFile, RichCompilationUnit] with
                       mutable.SynchronizedMap[AbstractFile, RichCompilationUnit] {
    override def put(key: AbstractFile, value: RichCompilationUnit): Option[RichCompilationUnit] = {
      val r = super.put(key, value)
      r
    }
    override def remove(key: AbstractFile): Option[RichCompilationUnit] = {
      val r = super.remove(key)
      r
    }
  }
  
  /** A set containing all those files that need to be removed
   *  Units are removed by getUnit, typically once a unit is finished compiled.
   */
  protected val toBeRemoved: MSet[AbstractFile] =
    new mutable.HashSet[AbstractFile] with mutable.SynchronizedSet[AbstractFile]

  /** A set containing all those files that need to be removed after a full background compiler run
   */
  protected val toBeRemovedAfterRun: MSet[AbstractFile] =
    new mutable.HashSet[AbstractFile] with mutable.SynchronizedSet[AbstractFile]
  
  def addCompilationUnit(file: AbstractFile, rcu: RichCompilationUnit): Option[RichCompilationUnit] = this.unitOfFile.put(file, rcu)
  def addCompilationUnits(rcus: ISeq[RichCompilationUnit]): Unit = {
    rcus.foreach(rcu => addCompilationUnit(rcu.cu.firstToken.file.file, rcu))
  }
  def removeCompilationUnit(file: AbstractFile): Option[RichCompilationUnit] = this.unitOfFile.remove(file)
  def getCompilationUnits: IMap[AbstractFile, RichCompilationUnit] = this.unitOfFile.toMap
  def getCompilationUnit(file: AbstractFile): Option[RichCompilationUnit] ={
    toBeRemoved.synchronized{
      for(f <- toBeRemoved) {
        informIDE("removed: " + file)
        unitOfFile -= file
      }
      toBeRemoved.clear()
    }
    this.unitOfFile.get(file)
  }
  def hasCompilationUnit(file: AbstractFile): Boolean = this.unitOfFile.contains(file)
  def managedFiles: ISet[AbstractFile] = this.unitOfFile.keySet.toSet
  
  case class RichCompilationUnit(cu: CompilationUnit) {
    /** The problems reported for this unit */
    val problems: MList[Problem] = mlistEmpty
  }
}
