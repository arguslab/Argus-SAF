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
import org.argus.jawa.core.{JavaKnowledge, JawaType}

/**
  * Created by fgwei on 6/15/17.
  */
class ListSuTest extends SuTestBase("List.safsu") {

  val thisInstance = PTAInstance(new JawaType("java.util.List"), defContext)
  val thisFact = new RFAFact(VarSlot("v0"), thisInstance)

  "Ljava/util/List;.containsAll:(Ljava/util/Collection;)Z" with_input () produce ()

  "Ljava/util/List;.add:(ILjava/lang/Object;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/List;.equals:(Ljava/lang/Object;)Z" with_input () produce ()

  "Ljava/util/List;.add:(Ljava/lang/Object;)Z" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/List;.addAll:(ILjava/util/Collection;)Z" with_input (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.util.Set"), defContext3)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext3), "items"), PTAConcreteStringInstance("String", defContext4))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext4)),
    new RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.util.Set"), defContext3)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext3), "items"), PTAConcreteStringInstance("String", defContext4))
  )

  "Ljava/util/List;.hashCode:()I" with_input () produce ()

  "Ljava/util/List;.clear:()V" with_input (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext3))
  ) produce thisFact

  "Ljava/util/List;.contains:(Ljava/lang/Object;)Z" with_input () produce ()

  "Ljava/util/List;.lastIndexOf:(Ljava/lang/Object;)I" with_input () produce ()

  "Ljava/util/List;.remove:(Ljava/lang/Object;)Z" with_input (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/util/List;.set:(ILjava/lang/Object;)Ljava/lang/Object;" with_input (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext4))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext4)),
    new RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext4))
  )

  "Ljava/util/List;.retainAll:(Ljava/util/Collection;)Z" with_input (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext3)),
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.Set"), defContext3)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext3), "items"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.Set"), defContext3)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext3), "items"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/util/List;.iterator:()Ljava/util/Iterator;" with_input (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.ListIterator").toUnknown, currentContext))
  )

  "Ljava/util/List;.get:(I)Ljava/lang/Object;" with_input (
    thisFact,
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown, currentContext)),
    new RFAFact(VarSlot("temp"), PTAInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown, currentContext))
  )

  "Ljava/util/List;.subList:(II)Ljava/util/List;" with_input (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.List").toUnknown, currentContext)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.List").toUnknown, currentContext), "items"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/List;.listIterator:(I)Ljava/util/ListIterator;" with_input (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.ListIterator").toUnknown, currentContext))
  )

  "Ljava/util/List;.isEmpty:()Z" with_input () produce ()

  "Ljava/util/List;.toArray:([Ljava/lang/Object;)[Ljava/lang/Object;" with_input (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.Object", 1), currentContext)),
    new RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.Object", 1), currentContext)), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/List;.listIterator:()Ljava/util/ListIterator;" with_input (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.ListIterator").toUnknown, currentContext))
  )

  "Ljava/util/List;.size:()I" with_input () produce ()

  "Ljava/util/List;.indexOf:(Ljava/lang/Object;)I" with_input () produce ()

  "Ljava/util/List;.toArray:()[Ljava/lang/Object;" with_input (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.Object", 1), currentContext)),
    new RFAFact(ArraySlot(PTAInstance(new JawaType("java.lang.Object", 1), currentContext)), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/List;.removeAll:(Ljava/util/Collection;)Z" with_input (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.Set"), defContext3)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext3), "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.Set"), defContext3)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext3), "items"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/List;.remove:(I)Ljava/lang/Object;" with_input (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/util/List;.addAll:(Ljava/util/Collection;)Z" with_input (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.Set"), defContext3)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext3), "items"), PTAConcreteStringInstance("String", defContext4))
  ) produce (
    thisFact,
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext2)),
    new RFAFact(FieldSlot(thisInstance, "items"), PTAConcreteStringInstance("String", defContext4)),
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.Set"), defContext3)),
    new RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.Set"), defContext3), "items"), PTAConcreteStringInstance("String", defContext4))
  )
}
