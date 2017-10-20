/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.summary.model

import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.rfa.RFAFact
import org.argus.jawa.core.JawaType

/**
  * Created by fgwei on 6/15/17.
  */
class MapSuTest extends SuTestBase("Map.safsu") {
  val thisInstance = PTAInstance(new JawaType("java.util.HashMap"), defContext)
  val thisFact = new RFAFact(VarSlot("v0"), thisInstance)
  val thisEntriesInstance = PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext)
  val thisEntriesFact = new RFAFact(FieldSlot(thisInstance, "entries"), thisEntriesInstance)

  "Ljava/util/HashMap;.<init>:()V" with_input (
    thisFact,
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), currentContext))
  )

  "Ljava/util/HashMap;.<init>:(IF)V" with_input (
    thisFact,
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), currentContext))
  )

  "Ljava/util/HashMap;.<init>:(I)V" with_input (
    thisFact,
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), currentContext))
  )

  "Ljava/util/HashMap;.<init>:(Ljava/util/Map;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.HashMap"), defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext2), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext2), "key"), PTAConcreteStringInstance("Key", defContext2)),
    new RFAFact(MapSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext2), PTAConcreteStringInstance("Key", defContext2)), PTAConcreteStringInstance("Value", defContext2))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext2)),
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.HashMap"), defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext2), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext2)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext2), "key"), PTAConcreteStringInstance("Key", defContext2)),
    new RFAFact(MapSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext2), PTAConcreteStringInstance("Key", defContext2)), PTAConcreteStringInstance("Value", defContext2))
  )

  "Ljava/util/Map;.clear:()V" with_input (
    thisFact,
    thisEntriesFact,
    new RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(MapSlot(thisEntriesInstance, PTAConcreteStringInstance("String", defContext2)), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    thisFact,
    thisEntriesFact
  )

  "Ljava/util/Map;.clone:()Ljava/lang/Object;" with_input (
    thisFact,
    thisEntriesFact,
    new RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(MapSlot(thisEntriesInstance, PTAConcreteStringInstance("String", defContext2)), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    thisFact,
    thisEntriesFact,
    new RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(MapSlot(thisEntriesInstance, PTAConcreteStringInstance("String", defContext2)), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.HashMap"), currentContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), currentContext), "entries"), thisEntriesInstance)
  )

  "Ljava/util/Map;.entrySet:()Ljava/util/Set;" with_input (
    thisFact,
    thisEntriesFact,
    new RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(MapSlot(thisEntriesInstance, PTAConcreteStringInstance("String", defContext2)), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    thisFact,
    thisEntriesFact,
    new RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(MapSlot(thisEntriesInstance, PTAConcreteStringInstance("String", defContext2)), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.HashSet"), currentContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashSet"), currentContext), "items"), thisEntriesInstance)
  )

  "Ljava/util/Map;.get:(Ljava/lang/Object;)Ljava/lang/Object;" with_input (
    thisFact,
    thisEntriesFact,
    new RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(MapSlot(thisEntriesInstance, PTAConcreteStringInstance("String", defContext2)), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext4))
  ) produce (
    thisFact,
    thisEntriesFact,
    new RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(MapSlot(thisEntriesInstance, PTAConcreteStringInstance("String", defContext2)), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext4)),
    new RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/util/Map;.keySet:()Ljava/util/Set;" with_input (
    thisFact,
    thisEntriesFact,
    new RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(MapSlot(thisEntriesInstance, PTAConcreteStringInstance("String", defContext2)), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    thisFact,
    thisEntriesFact,
    new RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(MapSlot(thisEntriesInstance, PTAConcreteStringInstance("String", defContext2)), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.HashSet"), currentContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashSet"), currentContext), "items"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/Map;.put:(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;" with_input (
    thisFact,
    thisEntriesFact,
    new RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisEntriesInstance, PTAConcreteStringInstance("key", defContext2)), PTAConcreteStringInstance("value", defContext3)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext4)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext4))
  ) produce (
    thisFact,
    thisEntriesFact,
    new RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("key", defContext2)),
    new RFAFact(MapSlot(thisEntriesInstance, PTAConcreteStringInstance("key", defContext2)), PTAConcreteStringInstance("value", defContext3)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext4)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext4)),
    new RFAFact(VarSlot("temp"), PTAConcreteStringInstance("value", defContext3)),
    new RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext4)),
    new RFAFact(MapSlot(thisEntriesInstance, PTAConcreteStringInstance("String", defContext4)), PTAConcreteStringInstance("String", defContext4))
  )

  "Ljava/util/Map;.putAll:(Ljava/util/Map;)V" with_input (
    thisFact,
    thisEntriesFact,
    new RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(MapSlot(thisEntriesInstance, PTAConcreteStringInstance("String", defContext2)), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.HashMap"), defContext4)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext4), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4), "key"), PTAConcreteStringInstance("String", defContext5)),
    new RFAFact(MapSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4), PTAConcreteStringInstance("String", defContext5)), PTAConcreteStringInstance("String", defContext5))
  ) produce (
    thisFact,
    thisEntriesFact,
    new RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(MapSlot(thisEntriesInstance, PTAConcreteStringInstance("String", defContext2)), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(FieldSlot(thisInstance, "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4)),
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.HashMap"), defContext4)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap"), defContext4), "entries"), PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4), "key"), PTAConcreteStringInstance("String", defContext5)),
    new RFAFact(MapSlot(PTAInstance(new JawaType("java.util.HashMap$Entries"), defContext4), PTAConcreteStringInstance("String", defContext5)), PTAConcreteStringInstance("String", defContext5))
  )

  "Ljava/util/Map;.remove:(Ljava/lang/Object;)Ljava/lang/Object;" with_input (
    thisFact,
    thisEntriesFact,
    new RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(MapSlot(thisEntriesInstance, PTAConcreteStringInstance("String", defContext2)), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    thisEntriesFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/util/Map;.values:()Ljava/util/Collection;" with_input (
    thisFact,
    thisEntriesFact,
    new RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(MapSlot(thisEntriesInstance, PTAConcreteStringInstance("String", defContext2)), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    thisFact,
    thisEntriesFact,
    new RFAFact(FieldSlot(thisEntriesInstance, "key"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(MapSlot(thisEntriesInstance, PTAConcreteStringInstance("String", defContext2)), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.HashSet"), currentContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashSet"), currentContext), "items"), PTAConcreteStringInstance("String", defContext3))
  )
}
