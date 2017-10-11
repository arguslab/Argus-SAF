/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.summary.model

import org.argus.amandroid.core.AndroidConstants
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.rfa.RFAFact
import org.argus.jawa.core.JawaType

/**
  * Created by fgwei on 6/24/17.
  */
class ActivitySuTest extends SuTestBase("Activity.safsu") {

  val thisInstance = PTAInstance(new JawaType(AndroidConstants.ACTIVITY), defContext)
  val thisFact = new RFAFact(VarSlot("v0"), thisInstance)
  val thisMIntentInstance = PTAInstance(new JawaType(AndroidConstants.INTENT), defContext)
  val thisMIntentFact = new RFAFact(FieldSlot(thisInstance, "mIntent"), thisMIntentInstance)

  "Landroid/app/Activity;.getIntent:()Landroid/content/Intent;" with_input (
    thisFact,
    thisMIntentFact
  ) produce (
    thisFact,
    thisMIntentFact,
    new RFAFact(VarSlot("temp"), thisMIntentInstance)
  )

  "Landroid/app/Activity;.setIntent:(Landroid/content/Intent;)V" with_input (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType(AndroidConstants.INTENT), defContext2))
  ) produce (
    thisFact,
    new RFAFact(VarSlot("v1"), PTAInstance(new JawaType(AndroidConstants.INTENT), defContext2)),
    new RFAFact(FieldSlot(thisInstance, "mIntent"), PTAInstance(new JawaType(AndroidConstants.INTENT), defContext2))
  )

  "Landroid/app/Activity;.getApplication:()Landroid/app/Application;" with_input (
    thisFact,
    thisMIntentFact
  ) produce (
    thisFact,
    thisMIntentFact,
    new RFAFact(VarSlot("temp"), PTAInstance(new JawaType("android.app.Application"), currentContext))
  )
}
