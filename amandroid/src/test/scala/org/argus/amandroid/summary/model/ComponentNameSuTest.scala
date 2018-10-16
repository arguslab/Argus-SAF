/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.summary.model

import org.argus.amandroid.core.AndroidConstants
import org.argus.jawa.flow.pta._
import org.argus.jawa.flow.pta.rfa.RFAFact
import org.argus.jawa.core.elements.{JavaKnowledge, JawaType}

/**
  * Created by fgwei on 6/24/17.
  */
class ComponentNameSuTest extends SuTestBase("ComponentName.safsu") {

  val thisInstance = PTAInstance(new JawaType(AndroidConstants.COMPONENT_NAME), defContext)
  val thisFact = RFAFact(VarSlot("v0"), thisInstance)
  val thisMClassInstance = PTAConcreteStringInstance("my.Class", defContext)
  val thisMClassFact = RFAFact(FieldSlot(thisInstance, "mClass"), thisMClassInstance)

  "Landroid/content/ComponentName;.<clinit>:()V" with_input () produce ()

  "Landroid/content/ComponentName;.<init>:(Landroid/content/Context;Ljava/lang/Class;)V" with_input (
    thisFact,
    RFAFact(VarSlot("v2"), PTAInstance(JavaKnowledge.CLASS, defContext2)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, defContext2), "name"), PTAConcreteStringInstance("my.Class", defContext2))
  ) produce (
    thisFact,
    RFAFact(VarSlot("v2"), PTAInstance(JavaKnowledge.CLASS, defContext2)),
    RFAFact(FieldSlot(PTAInstance(JavaKnowledge.CLASS, defContext2), "name"), PTAConcreteStringInstance("my.Class", defContext2)),
    RFAFact(FieldSlot(thisInstance, "mClass"), PTAConcreteStringInstance("my.Class", defContext2))
  )

  "Landroid/content/ComponentName;.<init>:(Landroid/content/Context;Ljava/lang/String;)V" with_input (
    thisFact,
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("my.Class", defContext2)),
  ) produce (
    thisFact,
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("my.Class", defContext2)),
    RFAFact(FieldSlot(thisInstance, "mClass"), PTAConcreteStringInstance("my.Class", defContext2))
  )

  "Landroid/content/ComponentName;.<init>:(Landroid/os/Parcel;)V" with_input () produce ()

  "Landroid/content/ComponentName;.<init>:(Ljava/lang/String;Ljava/lang/String;)V" with_input (
    thisFact,
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("my.Class", defContext2)),
  ) produce (
    thisFact,
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("my.Class", defContext2)),
    RFAFact(FieldSlot(thisInstance, "mClass"), PTAConcreteStringInstance("my.Class", defContext2))
  )

  "Landroid/content/ComponentName;.clone:()Landroid/content/ComponentName;" with_input (
    thisFact,
    thisMClassFact
  ) produce (
    thisFact,
    thisMClassFact,
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Landroid/content/ComponentName;.clone:()Ljava/lang/Object;" with_input (
    thisFact,
    thisMClassFact
  ) produce (
    thisFact,
    thisMClassFact,
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Landroid/content/ComponentName;.compareTo:(Landroid/content/ComponentName;)I" with_input () produce ()

  "Landroid/content/ComponentName;.compareTo:(Ljava/lang/Object;)I" with_input () produce ()

  "Landroid/content/ComponentName;.describeContents:()I" with_input () produce ()

  "Landroid/content/ComponentName;.equals:(Ljava/lang/Object;)Z" with_input () produce ()

  "Landroid/content/ComponentName;.flattenToShortString:()Ljava/lang/String;" with_input (
    thisFact,
    thisMClassFact
  ) produce (
    thisFact,
    thisMClassFact,
    RFAFact(VarSlot("temp"), thisMClassInstance)
  )

  "Landroid/content/ComponentName;.flattenToString:()Ljava/lang/String;" with_input (
    thisFact,
    thisMClassFact
  ) produce (
    thisFact,
    thisMClassFact,
    RFAFact(VarSlot("temp"), thisMClassInstance)
  )

  "Landroid/content/ComponentName;.getClassName:()Ljava/lang/String;" with_input (
    thisFact,
    thisMClassFact
  ) produce (
    thisFact,
    thisMClassFact,
    RFAFact(VarSlot("temp"), thisMClassInstance)
  )

  "Landroid/content/ComponentName;.getPackageName:()Ljava/lang/String;" with_input (
    thisFact,
    thisMClassFact
  ) produce (
    thisFact,
    thisMClassFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/content/ComponentName;.getShortClassName:()Ljava/lang/String;" with_input (
    thisFact,
    thisMClassFact
  ) produce (
    thisFact,
    thisMClassFact,
    RFAFact(VarSlot("temp"), thisMClassInstance)
  )

  "Landroid/content/ComponentName;.hashCode:()I" with_input () produce ()

  "Landroid/content/ComponentName;.readFromParcel:(Landroid/os/Parcel;)Landroid/content/ComponentName;" with_input (
    thisFact,
    thisMClassFact
  ) produce (
    thisFact,
    thisMClassFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType(AndroidConstants.COMPONENT_NAME), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType(AndroidConstants.COMPONENT_NAME), currentContext), "mClass"), PTAPointStringInstance(currentContext))
  )

  "Landroid/content/ComponentName;.toShortString:()Ljava/lang/String;" with_input (
    thisFact,
    thisMClassFact
  ) produce (
    thisFact,
    thisMClassFact,
    RFAFact(VarSlot("temp"), thisMClassInstance)
  )

  "Landroid/content/ComponentName;.toString:()Ljava/lang/String;" with_input (
    thisFact,
    thisMClassFact
  ) produce (
    thisFact,
    thisMClassFact,
    RFAFact(VarSlot("temp"), thisMClassInstance)
  )

  "Landroid/content/ComponentName;.unflattenFromString:(Ljava/lang/String;)Landroid/content/ComponentName;" with_input (
    thisFact,
    thisMClassFact
  ) produce (
    thisFact,
    thisMClassFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType(AndroidConstants.COMPONENT_NAME), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType(AndroidConstants.COMPONENT_NAME), currentContext), "mClass"), PTAPointStringInstance(currentContext))
  )

  "Landroid/content/ComponentName;.writeToParcel:(Landroid/content/ComponentName;Landroid/os/Parcel;)V" with_input () produce ()

  "Landroid/content/ComponentName;.writeToParcel:(Landroid/os/Parcel;I)V" with_input () produce ()
}
