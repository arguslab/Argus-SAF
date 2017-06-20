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
import org.argus.jawa.core.JawaType

import scala.language.implicitConversions

/**
  * Created by fgwei on 6/15/17.
  */
class SetSuTest extends SuTestBase("set.safsu") {
  "Ljava/util/Set;.add:(Ljava/lang/Object;)Z" with_vars (
    Some("temp"), Some("v0"), List("v1")
  ) with_input (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/util/Set;.clear:()V" with_vars (
    None, Some("v0"), List()
  ) with_input (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext))

  "Ljava/util/Set;.clone:()Ljava/lang/Object;" with_vars (
    Some("temp"), Some("v0"), List()
  ) with_input (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.Set"), defContext))
  )

  "Ljava/util/Set;.contains:(Ljava/lang/Object;)Z" with_vars (
    Some("temp"), Some("v0"), List("v1")
  ) with_input (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/Set;.isEmpty:()Z" with_vars (
    Some("temp"), Some("v0"), List()
  ) with_input (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/Set;.iterator:()Ljava/util/Iterator;" with_vars (
    Some("temp"), Some("v0"), List("v1")
  ) with_input (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.Iterator"), currentContext))
  )

  "Ljava/util/Set;.remove:(Ljava/lang/Object;)Z" with_vars (
    Some("temp"), Some("v0"), List("v1")
  ) with_input (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/util/Set;.size:()I" with_vars (
    Some("temp"), Some("v0"), List()
  ) with_input (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.Set"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext), "items"), PTAConcreteStringInstance("String", defContext2))
  )
}
