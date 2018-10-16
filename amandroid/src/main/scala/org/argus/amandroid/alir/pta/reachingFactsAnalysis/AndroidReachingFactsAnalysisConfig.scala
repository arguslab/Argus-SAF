/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.pta.reachingFactsAnalysis

import org.argus.amandroid.core.{AndroidConstants, AndroidGlobalConfig}
import org.argus.jawa.core.elements.JawaType
import org.argus.jawa.flow.Context
import org.argus.jawa.flow.pta._
import org.argus.jawa.flow.pta.rfa.RFAFact
import org.argus.jawa.core.util.{ISet, isetEmpty}
import org.argus.jawa.core.JawaMethod

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object AndroidReachingFactsAnalysisConfig {
  final var resolve_static_init: Boolean = AndroidGlobalConfig.settings.static_init
  final var parallel: Boolean = AndroidGlobalConfig.settings.parallel
  Context.init_context_length(AndroidGlobalConfig.settings.k_context)

  /**
    * generates and returns the initial facts corresponding to the "Intent" parameter of a dummyMain
    * the generated fact says that the param Intent is generated at the Center.
    */
  def getInitialFactsForMainEnvironment(dm: JawaMethod): ISet[RFAFact] = {
    require(dm.getName == AndroidConstants.MAINCOMP_ENV || dm.getName == AndroidConstants.COMP_ENV)
    var result = isetEmpty[RFAFact]
    val intentSlot = VarSlot(dm.getParamName(0))
    val context: Context = new Context(dm.getDeclaringClass.global.projectName)
    context.setContext(dm.getSignature, "L0000")
    val intentValue = PTAInstance(new JawaType(AndroidConstants.INTENT), context)
    result += RFAFact(intentSlot, intentValue)
    val mActionSlot = FieldSlot(intentValue, AndroidConstants.INTENT_ACTION)
    val mActionValue = PTAPointStringInstance(context)
    result += RFAFact(mActionSlot, mActionValue)
    val mCategoriesSlot = FieldSlot(intentValue, AndroidConstants.INTENT_CATEGORIES)
    val mCategoriesValue = PTAPointStringInstance(context)
    result += RFAFact(mCategoriesSlot, mCategoriesValue)
    val mTypeSlot = FieldSlot(intentValue, AndroidConstants.INTENT_MTYPE)
    val mTypeValue = PTAPointStringInstance(context)
    result += RFAFact(mTypeSlot, mTypeValue)
    val mDataSlot = FieldSlot(intentValue, AndroidConstants.INTENT_URI_DATA)
    val mDataValue = PTAPointStringInstance(context)
    result += RFAFact(mDataSlot, mDataValue)
    val mExtrasSlot = FieldSlot(intentValue, AndroidConstants.INTENT_EXTRAS)
    val mExtrasValue = PTAInstance(new JawaType(AndroidConstants.BUNDLE), context)
    result += RFAFact(mExtrasSlot, mExtrasValue)
    result
  }

}
