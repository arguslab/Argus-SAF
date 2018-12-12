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
import org.argus.jawa.core.elements.{JavaKnowledge, JawaType}

/**
  * Created by fgwei on 6/15/17.
  */
class ListSuTest extends SuTestBase("List.safsu") {

  val thisInstance = PTAInstance(new JawaType("java.util.List"), defContext)
  val thisFact = RFAFact(VarSlot("v0"), thisInstance)

  "Ljava/util/List;.containsAll:(Ljava/util/Collection;)Z" with_input () produce ()

  "Ljava/util/List;.add:(ILjava/lang/Object;)V" with_input (
    thisFact,
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/List;.equals:(Ljava/lang/Object;)Z" with_input () produce ()

  "Ljava/util/List;.add:(Ljava/lang/Object;)Z" with_input (
    thisFact,
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/List;.addAll:(ILjava/util/Collection;)Z" with_input (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.util.Set"), defContext3)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext3), "items"), PTAConcreteStringInstance("String", defContext4))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext4)),
    RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.util.Set"), defContext3)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext3), "items"), PTAConcreteStringInstance("String", defContext4))
  )

  "Ljava/util/List;.hashCode:()I" with_input () produce ()

  "Ljava/util/List;.clear:()V" with_input (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext3))
  ) produce thisFact

  "Ljava/util/List;.contains:(Ljava/lang/Object;)Z" with_input () produce ()

  "Ljava/util/List;.lastIndexOf:(Ljava/lang/Object;)I" with_input () produce ()

  "Ljava/util/List;.remove:(Ljava/lang/Object;)Z" with_input (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/util/List;.set:(ILjava/lang/Object;)Ljava/lang/Object;" with_input (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext4))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext4)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext4))
  )

  "Ljava/util/List;.retainAll:(Ljava/util/Collection;)Z" with_input (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.Set"), defContext3)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext3), "items"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.Set"), defContext3)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext3), "items"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/util/List;.iterator:()Ljava/util/Iterator;" with_input (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.ListIterator").toUnknown, currentContext))
  )

  "Ljava/util/List;.get:(I)Ljava/lang/Object;" with_input thisFact produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAInstance(JavaKnowledge.OBJECT.toUnknown, thisInstance.defSite)),
    RFAFact(VarSlot("temp"), PTAInstance(JavaKnowledge.OBJECT.toUnknown, thisInstance.defSite))
  )

  "Ljava/util/List;.subList:(II)Ljava/util/List;" with_input (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.List").toUnknown, currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.List").toUnknown, currentContext), "items"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/List;.listIterator:(I)Ljava/util/ListIterator;" with_input (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.ListIterator").toUnknown, currentContext))
  )

  "Ljava/util/List;.isEmpty:()Z" with_input () produce ()

  "Ljava/util/List;.toArray:([Ljava/lang/Object;)[Ljava/lang/Object;" with_input (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.Object", 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.Object", 1), currentContext)), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/List;.listIterator:()Ljava/util/ListIterator;" with_input (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.ListIterator").toUnknown, currentContext))
  )

  "Ljava/util/List;.size:()I" with_input () produce ()

  "Ljava/util/List;.indexOf:(Ljava/lang/Object;)I" with_input () produce ()

  "Ljava/util/List;.toArray:()[Ljava/lang/Object;" with_input (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.Object", 1), currentContext)),
    RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.Object", 1), currentContext)), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/List;.removeAll:(Ljava/util/Collection;)Z" with_input (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.Set"), defContext3)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext3), "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.Set"), defContext3)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext3), "items"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/List;.remove:(I)Ljava/lang/Object;" with_input (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/List;.addAll:(Ljava/util/Collection;)Z" with_input (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.Set"), defContext3)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext3), "items"), PTAConcreteStringInstance("String", defContext4))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext4)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.Set"), defContext3)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext3), "items"), PTAConcreteStringInstance("String", defContext4))
  )
}
