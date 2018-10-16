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
import org.argus.jawa.core.elements.JawaType

/**
  * Created by fgwei on 6/24/17.
  */
class ActivitySuTest extends SuTestBase("Activity.safsu") {

  val thisInstance = PTAInstance(new JawaType(AndroidConstants.ACTIVITY), defContext)
  val thisFact = RFAFact(VarSlot("v0"), thisInstance)
  val thisMIntentInstance = PTAInstance(new JawaType(AndroidConstants.INTENT), defContext)
  val thisMIntentFact = RFAFact(FieldSlot(thisInstance, "mIntent"), thisMIntentInstance)

  "Landroid/app/Activity;.getIntent:()Landroid/content/Intent;" with_input (
    thisFact,
    thisMIntentFact
  ) produce (
    thisFact,
    thisMIntentFact,
    RFAFact(VarSlot("temp"), thisMIntentInstance)
  )

  "Landroid/app/Activity;.setIntent:(Landroid/content/Intent;)V" with_input (
    thisFact,
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType(AndroidConstants.INTENT), defContext2))
  ) produce (
    thisFact,
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType(AndroidConstants.INTENT), defContext2)),
    RFAFact(FieldSlot(thisInstance, "mIntent"), PTAInstance(new JawaType(AndroidConstants.INTENT), defContext2))
  )

  "Landroid/app/Activity;.getApplication:()Landroid/app/Application;" with_input (
    thisFact,
    thisMIntentFact
  ) produce (
    thisFact,
    thisMIntentFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("android.app.Application"), currentContext))
  )
}
