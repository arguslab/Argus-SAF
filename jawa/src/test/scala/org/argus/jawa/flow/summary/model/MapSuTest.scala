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
class MapSuTest extends SuTestBase("Map.safsu") {
  val thisInstance = PTAInstance(new JawaType("java.util.HashMap"), defContext)
  val thisFact = RFAFact(VarSlot("v0"), thisInstance)
  val thisEntriesInstance = PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)
  val thisEntriesFact = RFAFact(FieldSlot(thisInstance, "entries"), thisEntriesInstance)

  "Ljava/util/HashMap;.<init>:()V" with_input thisFact produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), currentContext))
  )

  "Ljava/util/HashMap;.<init>:(IF)V" with_input thisFact produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), currentContext))
  )

  "Ljava/util/HashMap;.<init>:(I)V" with_input thisFact produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), currentContext))
  )

  "Ljava/util/HashMap;.<init>:(Ljava/util/Map;)V" with_input (
    thisFact,
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.HashMap"), defContext2)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext2), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext2)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext2), "key"), PTAConcreteStringInstance("Key", defContext2)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext2), "value"), PTAConcreteStringInstance("Value", defContext2))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext2)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.HashMap"), defContext2)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext2), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext2)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext2), "key"), PTAConcreteStringInstance("Key", defContext2)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext2), "value"), PTAConcreteStringInstance("Value", defContext2))
  )

  "Ljava/util/Map;.clear:()V" with_input (
    thisFact,
    thisEntriesFact,
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    thisFact,
    thisEntriesFact
  )

  "Ljava/util/Map;.clone:()Ljava/lang/Object;" with_input (
    thisFact,
    thisEntriesFact,
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    thisFact,
    thisEntriesFact,
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.HashMap"), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), currentContext), "entries"), thisEntriesInstance)
  )

  "Ljava/util/Map;.entrySet:()Ljava/util/Set;" with_input (
    thisFact,
    thisEntriesFact,
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    thisFact,
    thisEntriesFact,
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.HashSet"), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashSet"), currentContext), "items"), thisEntriesInstance)
  )

  "Ljava/util/Map;.get:(Ljava/lang/Object;)Ljava/lang/Object;" with_input (
    thisFact,
    thisEntriesFact,
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext4))
  ) produce (
    thisFact,
    thisEntriesFact,
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext4)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/util/Map;.keySet:()Ljava/util/Set;" with_input (
    thisFact,
    thisEntriesFact,
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    thisFact,
    thisEntriesFact,
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.HashSet"), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashSet"), currentContext), "items"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/Map;.put:(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;" with_input (
    thisFact,
    thisEntriesFact,
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("value", defContext3)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext4)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext4))
  ) produce (
    thisFact,
    thisEntriesFact,
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("value", defContext3)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext4)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext4)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("value", defContext3)),
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext4)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("String", defContext4))
  )

  "Ljava/util/Map;.putAll:(Ljava/util/Map;)V" with_input (
    thisFact,
    thisEntriesFact,
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.HashMap"), defContext4)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext4), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4), "key"), PTAConcreteStringInstance("String", defContext5)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4), "value"), PTAConcreteStringInstance("String", defContext5))
  ) produce (
    thisFact,
    thisEntriesFact,
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(FieldSlot(thisInstance, "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.HashMap"), defContext4)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext4), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4), "key"), PTAConcreteStringInstance("String", defContext5)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4), "value"), PTAConcreteStringInstance("String", defContext5))
  )

  "Ljava/util/Map;.remove:(Ljava/lang/Object;)Ljava/lang/Object;" with_input (
    thisFact,
    thisEntriesFact,
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    thisEntriesFact,
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/util/Map;.values:()Ljava/util/Collection;" with_input (
    thisFact,
    thisEntriesFact,
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    thisFact,
    thisEntriesFact,
    RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisEntriesInstance, "value"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.HashSet"), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashSet"), currentContext), "items"), PTAConcreteStringInstance("String", defContext3))
  )
}
