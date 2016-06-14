/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir

import org.argus.jawa.core.Signature
import org.sireum.util._

object Context {
  private var k: Int = 1
  def init_context_length(k: Int) = this.k = k
}

/**
 * @author @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class Context {
  import Context._
  def copy: Context = {
    val clone = new Context
    clone.callStack ++= this.callStack
    clone
  }
//  def copy(c: Context) = this.callStack = c.getContext
  def setContext(callStack2: IList[(Signature, String)]) = {
    callStack.prependAll(callStack2)
    val size = length
    if(size > k + 1) {
      callStack.remove(size - (k + 1))
    }
  }
  private val callStack: MList[(Signature, String)] = mlistEmpty
  def length: Int = this.callStack.size
  def setContext(pSig: Signature, loc: String) = {
    if(length <= k){
      callStack.prepend((pSig, loc))
    } else {
      callStack.remove(length - 1)
      callStack.prepend((pSig, loc))
    }
    this
  }
  
  def getCurrentLocUri: String = {
    if(callStack.isEmpty) ""
    else callStack.head._2
  }
  
  /**
   * update current context using another context.
   */
  def updateContext(context2: Context) = {
    val callStack2 = context2.getContext
    callStack.prependAll(callStack2)
    val size = length
    if(size > k + 1) {
      callStack.remove(size - (k + 1))
    }
  }
  
  /**
   * remove current top context
   */
  def removeTopContext() = {
    if(callStack.nonEmpty)
    	  callStack.remove(0)
    this
  }
  
  def getContext: IList[(Signature, String)] = this.callStack.toList
  def getLocUri: String = getContext.head._2
  def getMethodSig = getContext.head._1
  def isDiff(c: Context): Boolean = this != c
  override def equals(a: Any): Boolean = {
    a match {
      case context: Context => this.callStack.toList == context.getContext
      case _ => false
    }
  }
  override def hashCode() = if (this.callStack == null) 0 else this.callStack.hashCode
  override def toString = {
    val sb = new StringBuilder
    this.callStack.foreach{
      case(sig, str) =>
        sb.append("(" + sig.methodName)
          
        if(str.lastIndexOf('.') > 0)
          sb.append("," + str.substring(str.lastIndexOf('.') + 1, str.lastIndexOf(':')) + ")")
        else sb.append("," + str + ")")
    }
    sb.toString.intern()
  }
  def toFullString = {
    val sb = new StringBuilder
    this.callStack.foreach{
      case(sig, str) =>
        sb.append("(" + sig)
        sb.append("," + str + ")")
    }
    sb.toString.intern()
  }
}
