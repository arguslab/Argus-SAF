/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.summary.model

import org.argus.jawa.flow.pta._
import org.argus.jawa.flow.pta.rfa.RFAFact
import org.argus.jawa.core.elements.JavaKnowledge

/**
  * Created by fgwei on 6/15/17.
  */
class ObjectSuTest extends SuTestBase("Object.safsu") {
  val thisInstance = PTAInstance(JavaKnowledge.OBJECT, defContext)
  val thisFact = RFAFact(VarSlot("v0"), thisInstance)

  "Ljava/lang/Object;.<init>:()V" with_input thisFact produce thisFact

  "Ljava/lang/Object;.clone:()Ljava/lang/Object;" with_input thisFact produce (
    thisFact,
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/Object;.equals:(Ljava/lang/Object;)B" with_input thisFact produce thisFact

  "Ljava/lang/Object;.finalize:()V" with_input thisFact produce thisFact

  "Ljava/lang/Object;.getClass:()Ljava/lang/Class;"with_input thisFact produce (
    thisFact,
    RFAFact(VarSlot("temp"), PTAInstance(JavaKnowledge.CLASS, currentContext)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, currentContext), "name"), PTAConcreteStringInstance("java.lang.Object", currentContext))
  )

  "Ljava/lang/Object;.hashCode:()I" with_input thisFact produce thisFact

  "Ljava/lang/Object;.notify:()V" with_input thisFact produce thisFact

  "Ljava/lang/Object;.notifyAll:()V" with_input thisFact produce thisFact

  "Ljava/lang/Object;.toString:()Ljava/lang/String;" with_input thisFact produce (
    thisFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/Object;.wait:()V" with_input thisFact produce thisFact

  "Ljava/lang/Object;.wait:(J)V" with_input thisFact produce thisFact

  "Ljava/lang/Object;.wait:(JI)V" with_input thisFact produce thisFact
}
