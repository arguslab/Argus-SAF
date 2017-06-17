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
class MapSuTest extends SuTestBase("map.safsu") {
  "Ljava/util/Map;.clear:()V" with_vars (None, Some("v0"), List()) with_input (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext3))
  ) produce new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext))

  "Ljava/util/Map;.clone:()Ljava/lang/Object;" with_vars (Some("temp"), Some("v0"), List()) with_input (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.HashMap"), defContext))
  )

  "Ljava/util/Map;.entrySet:()Ljava/util/Set;" with_vars (Some("temp"), Some("v0"), List()) with_input (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.HashSet"), currentContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashSet"), currentContext), "items"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext))
  )

  "Ljava/util/Map;.get:(Ljava/lang/Object;)Ljava/lang/Object;" with_vars (Some("temp"), Some("v0"), List("v1")) with_input (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/util/Map;.keySet:()Ljava/util/Set;" with_vars (Some("temp"), Some("v0"), List()) with_input (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.HashSet"), currentContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashSet"), currentContext), "items"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/Map;.put:(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;" with_vars (Some("temp"), Some("v0"), List("v1", "v2")) with_input (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext4)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext4))
  ) produce (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext4)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext4)),
    new RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext4)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext4))
  )

  "Ljava/util/Map;.putAll:(Ljava/util/Map;)V" with_vars (None, Some("v0"), List("v1")) with_input (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.HashMap"), defContext4)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext4), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4), "key"), PTAConcreteStringInstance("String", defContext5)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4), "value"), PTAConcreteStringInstance("String", defContext5))
  ) produce (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.HashMap"), defContext4)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext4), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4), "key"), PTAConcreteStringInstance("String", defContext5)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4), "value"), PTAConcreteStringInstance("String", defContext5))
  )

  "Ljava/util/Map;.remove:(Ljava/lang/Object;)Ljava/lang/Object;" with_vars (Some("temp"), Some("v0"), List("v1")) with_input (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext4))
  ) produce (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext4)),
    new RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/util/Map;.values:()Ljava/util/Collection;" with_vars (Some("temp"), Some("v0"), List()) with_input (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    new RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.util.HashMap"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext), "value"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.HashSet"), currentContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashSet"), currentContext), "items"), PTAConcreteStringInstance("String", defContext3))
  )
}
