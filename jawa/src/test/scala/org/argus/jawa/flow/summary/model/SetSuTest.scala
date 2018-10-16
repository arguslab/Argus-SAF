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
import org.argus.jawa.core.elements.JawaType

/**
  * Created by fgwei on 6/15/17.
  */
class SetSuTest extends SuTestBase("Set.safsu") {
  "Ljava/util/Set;.add:(Ljava/lang/Object;)Z" with_input (
    RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/util/Set;.clear:()V" with_input (
    RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext))

  "Ljava/util/Set;.clone:()Ljava/lang/Object;" with_input (
    RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.Set"), defContext))
  )

  "Ljava/util/Set;.contains:(Ljava/lang/Object;)Z" with_input (
    RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/Set;.isEmpty:()Z" with_input (
    RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/Set;.iterator:()Ljava/util/Iterator;" with_input (
    RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.Iterator").toUnknown, currentContext))
  )

  "Ljava/util/Set;.remove:(Ljava/lang/Object;)Z" with_input (
    RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/util/Set;.size:()I" with_input (
    RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  )
}
