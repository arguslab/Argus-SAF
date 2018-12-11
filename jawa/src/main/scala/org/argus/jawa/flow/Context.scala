/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow

import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util._

object Context {
  private var k: Int = 1
  def init_context_length(k: Int): Unit = this.k = k
}

/**
 * @author @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class Context(val application: FileResourceUri) {
  import Context._
  def copy: Context = {
    val clone = new Context(application)
    clone.callStack ++= this.callStack
    clone
  }
  def setContext(callStack2: IList[(Signature, String)]): Unit = {
    callStack.prependAll(callStack2)
    val size = length
    if(size > k + 1) {
      callStack.remove(size - (k + 1))
    }
  }
  private val callStack: MList[(Signature, String)] = mlistEmpty
  def length: Int = this.callStack.size
  def setContext(pSig: Signature, loc: String): Context = {
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
  def updateContext(context2: Context): Unit = {
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
  def removeTopContext(): Context = {
    if(callStack.nonEmpty)
    	  callStack.remove(0)
    this
  }
  
  def getContext: IList[(Signature, String)] = this.callStack.toList
  def getLocUri: String = getContext.head._2
  def getMethodSig: Signature = getContext.head._1
  def isDiff(c: Context): Boolean = this != c
  override def equals(a: Any): Boolean = {
    a match {
      case context: Context => this.callStack.toList == context.getContext
      case _ => false
    }
  }
  override def hashCode(): Int = (application, this.callStack).hashCode()
  override def toString: String = {
    val sb = new StringBuilder
    this.callStack.foreach{
      case(sig, str) =>
        sb.append("(" + sig.classTyp.simpleName + "." + sig.methodName)
        sb.append("," + str + ")")
    }
    sb.toString.intern()
  }
  def toFullString: String = {
    val sb = new StringBuilder
    this.callStack.foreach{
      case(sig, str) =>
        sb.append("(" + sig + "," + str + ")")
    }
    sb.toString.intern()
  }
}
