/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.summaryBasedAnalysis.model

import org.argus.amandroid.core.AndroidConstants
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.RFAFact
import org.argus.jawa.core.{JavaKnowledge, JawaType}

/**
  * Created by fgwei on 6/26/17.
  */
class ContextSuTest extends SuTestBase("Context.safsu") {

  val thisInstance = PTAInstance(new JawaType(AndroidConstants.ACTIVITY), defContext)
  val thisFact = new RFAFact(VarSlot("v0"), thisInstance)
  val thisBaseInstance = PTAInstance(new JawaType(AndroidConstants.CONTEXT).toUnknown, defContext)
  val thisBaseFact = new RFAFact(FieldSlot(thisInstance, "mBase"), thisBaseInstance)
  val thisMIntentInstance = PTAInstance(new JawaType(AndroidConstants.INTENT), defContext)
  val thisMIntentFact = new RFAFact(FieldSlot(thisInstance, "mIntent"), thisMIntentInstance)

  "Landroid/content/Context;.getSystemService:(Ljava/lang/String;)Ljava/lang/Object;" with_input (
    thisFact,
    thisBaseFact
  ) produce (
    thisFact,
    thisBaseFact,
    new RFAFact(VarSlot("temp"), PTAInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown, currentContext))
  )

  "Landroid/content/Context;.getBaseContext:()Landroid/content/Context;" with_input (
    thisFact,
    thisBaseFact
  ) produce (
    thisFact,
    thisBaseFact,
    new RFAFact(VarSlot("temp"), thisBaseInstance)
  )

  "Landroid/content/Context;.getApplicationContext:()Landroid/content/Context;" with_input (
    thisFact,
    thisBaseFact
  ) produce (
    thisFact,
    thisBaseFact,
    new RFAFact(VarSlot("temp"), thisBaseInstance)
  )

  "Landroid/content/ContextWrapper;.registerReceiver:(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;" with_input (
    thisFact,
    thisBaseFact,
    thisMIntentFact
  ) produce (
    thisFact,
    thisBaseFact,
    thisMIntentFact,
    new RFAFact(VarSlot("temp"), thisMIntentInstance)
  )

  "Landroid/content/ContextWrapper;.registerReceiver:(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;" with_input (
    thisFact,
    thisBaseFact,
    thisMIntentFact
  ) produce (
    thisFact,
    thisBaseFact,
    thisMIntentFact,
    new RFAFact(VarSlot("temp"), thisMIntentInstance)
  )
}
