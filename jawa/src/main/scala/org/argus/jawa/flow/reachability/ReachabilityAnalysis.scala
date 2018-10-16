/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.reachability

import org.argus.jawa.core.Global
import org.argus.jawa.core.elements.{JawaType, Signature}
import org.argus.jawa.core.util._
import org.argus.jawa.flow.cg.CHA


/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object ReachabilityAnalysis {
  /**
    * Get all reachable procedures of given type set.
    */
  def getReachableMethodsByCHA(global: Global, typs: ISet[JawaType]): IMap[JawaType, ISet[Signature]] = {
    val map: IMap[JawaType, ISet[Signature]] = typs.map { typ =>
      typ -> {
        global.getClazz(typ) match {
          case Some(c) => c.getDeclaredMethods.map(_.getSignature)
          case None => isetEmpty[Signature]
        }
      }
    }.toMap
    val cg = CHA(global, map.flatMap(_._2).toSet)
    map.map { case (typ, sigs) =>
      typ -> cg.getReachableMethods(sigs)
    }
  }
}
