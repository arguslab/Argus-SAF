/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir

import org.sireum.util._

import org.argus.jawa.alir.sideEffectAnalysis.InterproceduralSideEffectAnalysisResult
import org.argus.jawa.core.Signature

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object LibSideEffectProvider {
  var ipsear: InterproceduralSideEffectAnalysisResult = null
	def init(ipsear: InterproceduralSideEffectAnalysisResult) = {
	  this.ipsear = ipsear
	}
  
//  def init(zipFile: File): Unit = {
//    val reader = new GZIPInputStream(new FileInputStream(zipFile))
//    val interPSEA = AndroidXStream.fromXml(reader).asInstanceOf[InterproceduralSideEffectAnalysisResult]
//    reader.close()
//    this.ipsear = interPSEA
//  }
  
//  def init: Unit = {
//    
//    init(AndroidGlobal"/LibSummary/AndroidLibSideEffectResult.xml.zip")
//  }
  
  def isDefined: Boolean = ipsear != null
  
  def getInfluencedFields(position: Int, calleeSig: Signature): ISet[String] = {
    require(isDefined)
    val resultopt = this.ipsear.result(calleeSig)
    resultopt match{
      case Some(result) => result.writeMap.getOrElse(position, isetEmpty)
      case None => Set("ALL")
    }
  }
}
