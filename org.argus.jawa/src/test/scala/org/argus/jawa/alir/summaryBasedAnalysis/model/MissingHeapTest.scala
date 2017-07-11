/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.summaryBasedAnalysis.model

import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.RFAFact
import org.argus.jawa.core.{JavaKnowledge, JawaType}

/**
  * Created by fgwei on 7/11/17.
  */
class MissingHeapTest extends SuTestBase("map.safsu") {
  val thisInstance = PTAInstance(new JawaType("java.util.HashMap"), defContext)
  val thisFact = new RFAFact(VarSlot("v0"), thisInstance)

  "Ljava/util/Map;.get:(Ljava/lang/Object;)Ljava/lang/Object;" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext4))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), currentContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), currentContext), "key"), PTAConcreteStringInstance("String", defContext4)),
    new RFAFact(MapSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), currentContext), PTAConcreteStringInstance("String", defContext4)), PTAInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown, currentContext)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext4)),
    new RFAFact(VarSlot("temp"), PTAInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown, currentContext))
  )
}
