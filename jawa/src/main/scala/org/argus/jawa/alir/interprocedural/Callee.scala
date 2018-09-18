/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.interprocedural

import org.argus.jawa.alir.pta.rfa.RFAFact
import org.argus.jawa.alir.pta.{Instance, VarSlot}
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
trait Callee {
  def callee: Signature
}

trait RFACallee extends Callee {
  def mapFactsToCallee: (ISet[RFAFact], IList[String], IList[String]) => ISet[RFAFact]
}

abstract class DirectCallee extends RFACallee {
  def mapFactsToCallee: (ISet[RFAFact], IList[String], IList[String]) => ISet[RFAFact] = (factsToCallee, args, params) => {
    val varFacts = factsToCallee.filter(f=>f.s.isInstanceOf[VarSlot])
    val argSlots = args.map(VarSlot)
    val paramSlots = params.map(VarSlot)
    val result = msetEmpty[RFAFact]

    for(i <- argSlots.indices){
      val argSlot = argSlots(i)
      val paramSlot = paramSlots(i)
      varFacts.foreach{ fact =>
        if(fact.s.getId == argSlot.getId) result += RFAFact(paramSlot, fact.v)
      }
    }
    factsToCallee -- varFacts ++ result
  }
}

abstract class IndirectCallee extends RFACallee

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class InstanceCallee(callee: Signature, ins: Instance) extends DirectCallee

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class UnknownCallee(callee: Signature) extends DirectCallee

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class StaticCallee(callee: Signature) extends DirectCallee

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
final case class IndirectInstanceCallee(callee: Signature, ins: Instance, mapFactsToCallee: (ISet[RFAFact], IList[String], IList[String]) => ISet[RFAFact]) extends IndirectCallee