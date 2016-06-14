/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.reachability

import org.argus.jawa.alir.pta.suspark.InterproceduralSuperSpark
import org.argus.jawa.core.{Global, Signature}
import org.sireum.util.ISet


/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object ReachabilityAnalysis {
  
  /**
    * Get all reachable procedures of given procedure set.
    *
    * @param global Jawa global
    * @param procedures Procedures to start the reachability analysis.
    * @return Set of reachable procedure resource uris from initial set
    */
  def getReachableMethods(global: Global, procedures: ISet[Signature]): ISet[Signature] = {
    val idfg = InterproceduralSuperSpark(global, procedures)
    idfg.icfg.getCallGraph.getReachableMethods(procedures)
  }

def getReachableMethodsBySBCG(global: Global, procedures: ISet[Signature]): ISet[Signature] = {
  val cg = SignatureBasedCallGraph(global, procedures)
  cg.getReachableMethods(procedures)
}
//
//def getBackwardReachability(apiSigs: Set[String], par: Boolean): Map[String, Set[JawaMethod]] = {
//  BackwardCallChain.getReachableMethods(apiSigs, par)
//}
//
//def getBackwardReachability(apiSig: String, par: Boolean): Set[JawaMethod] = {
//  BackwardCallChain.getReachableMethods(apiSig, par)
//}
//
//def getBackwardReachabilityForSubSig(apiSubSig: String, par: Boolean): Set[JawaMethod] = {
//  BackwardCallChain.getReachableMethodsBySubSig(apiSubSig, par)
//}
}
