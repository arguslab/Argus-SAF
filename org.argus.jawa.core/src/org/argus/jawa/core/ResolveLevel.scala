/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
trait ResolveLevel {
  
  /**
   * resolving level of current class
   */
  protected var resolvingLevel: ResolveLevel.Value = ResolveLevel.NOT_LOADED
  
  /**
   * check whether we already resolved to desired level
   */
  def checkLevelAndThrowException(level: ResolveLevel.Value, message: String) = {
    if(this.resolvingLevel < level) {
      val msg = "desired level: " + level + ". resolving level: " + this.resolvingLevel + " message: " + message 
      throw new RuntimeException(msg)
    }
  }
  
  /**
   * check whether we already resolved to desired level
   */
  def checkLevel(level: ResolveLevel.Value) = this.resolvingLevel >= level
  
  /**
   * return resolving level
   */
  def getResolvingLevel = this.resolvingLevel
  
  /**
   * set resolving level
   */
  def setResolvingLevel(level: ResolveLevel.Value)
}

/**
 * enum of all the valid resolve level of class
 */
  
object ResolveLevel extends Enumeration {
  val NOT_LOADED, HIERARCHY, BODY = Value
}
