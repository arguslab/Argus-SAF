/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.reachability

import org.argus.jawa.alir.pta.suspark.InterProceduralSuperSpark
import org.argus.jawa.core.{Global, JawaType, Signature}
import org.argus.jawa.core.util._


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
    val idfg = InterProceduralSuperSpark(global, procedures)
    idfg.icfg.getCallGraph.getReachableMethods(procedures)
  }

  def getReachableMethodsBySBCG(global: Global, typs: ISet[JawaType]): IMap[JawaType, ISet[Signature]] = {
    val map: IMap[JawaType, ISet[Signature]] = typs.map { typ =>
      typ -> {
        global.getClazz(typ) match {
          case Some(c) => c.getDeclaredMethods.map(_.getSignature)
          case None => isetEmpty[Signature]
        }
      }
    }.toMap
    val cg = SignatureBasedCallGraph(global, map.flatMap(_._2).toSet)
    map.map { case (typ, sigs) =>
      typ -> cg.getReachableMethods(sigs)
    }
  }
}
