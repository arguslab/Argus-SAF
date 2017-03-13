/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.pta.reachingFactsAnalysis

import org.argus.jawa.core.{JawaClass, ScopeManager}
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class AndroidRFAScopeManager extends ScopeManager{
  private var packages: ISet[String] = isetEmpty
  private var includeMode = true
  def setMode(includeMode: Boolean) = this.includeMode = includeMode
  /**
   * return true means use in scope mode, any package defined in ScopeManager will be keep
   * during the analysis, and vice versa.
   */
  def isIncludeMode: Boolean = this.includeMode

  def addPackage(packageName: String) = this.packages += packageName
  def addPackages(packageNames: ISet[String]) = this.packages ++= packageNames
  def removePackage(packageName: String) = this.packages -= packageName
  def removePackages(packageNames: ISet[String]) = this.packages --= packageNames

  /**
   * return true if given package name contained in the scope manager
   */
  def contains(packageName: String): Boolean = this.packages.contains(packageName)
  def clear() = this.packages = isetEmpty

  /**
   * return true if given record needs to be bypassed
   */
  def shouldBypass(rec: JawaClass): Boolean = {
    (rec.isSystemLibraryClass || rec.isUserLibraryClass) &&
    {
      if(isIncludeMode){
        if(rec.getPackage.isDefined) !contains(rec.getPackage.get.toPkgString(".")) else true
      } else {
        if(rec.getPackage.isDefined) contains(rec.getPackage.get.toPkgString(".")) else false
      }
    }
  }
}
