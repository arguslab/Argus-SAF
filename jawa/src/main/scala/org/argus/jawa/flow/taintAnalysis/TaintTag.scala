/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.taintAnalysis

import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class TaintTag {
  private val tags: MSet[String] = msetEmpty
  
  /**
   * tagStr: Taint tag has to be following format: WEB|XSS|LOCATION ...
   */
  def setTags(tagStr: String): Unit = {
    val ts = tagStr.split("|")
    this.tags ++= ts
  }
  
  def getTags: Set[String] = {
    this.tags.toSet
  }
  
  /**
   * str: format --> +WEB+XSS-LOCATION ...
   */
  def parse(str: String): Unit = {
    val it = str.iterator
    val sb = new StringBuilder
    var flag = 0
    while(it.hasNext){
      val s = it.next()
      if(flag != 0){
        if(s == ' ' || s == '+' || s == '-' || !it.hasNext){
          if(!it.hasNext) sb.append(s)
          if(flag == 1) tags += sb.toString()
          else if(flag == 2) tags -= sb.toString()
          sb.clear()
          flag = 0
        }
        else sb.append(s)
      }
      if(s == '+') flag = 1
      else if(s == '-') flag = 2
    }
  }
  
  override def toString: String = {
    val sb = new StringBuilder
    tags.foreach{
      tag =>
        sb.append(tag + " ")
    }
    sb.toString()
  }
}
