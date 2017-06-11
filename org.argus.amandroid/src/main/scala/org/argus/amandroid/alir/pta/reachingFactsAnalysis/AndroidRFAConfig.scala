/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.pta.reachingFactsAnalysis

import org.argus.amandroid.core.AndroidConstants
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, SimHeap}
import org.argus.jawa.core.{JavaKnowledge, JawaMethod, JawaType}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object AndroidRFAConfig {
  /**
   * generates and returns the initial facts corresponding to the "Intent" parameter of a dummyMain 
   * the generated fact says that the param Intent is generated at the Center.
   */
  def getInitialFactsForMainEnvironment(dm: JawaMethod)(implicit factory: SimHeap): ISet[RFAFact] = {
    require(dm.getName == AndroidConstants.MAINCOMP_ENV || dm.getName == AndroidConstants.COMP_ENV)
    var result = isetEmpty[RFAFact]
    val intentSlot = VarSlot(dm.getParamName(0), isBase = false, isArg = false)
    val context: Context = new Context(dm.getDeclaringClass.global.projectName)
    context.setContext(dm.getSignature, "L0000")
    val intentValue = PTAInstance(new JawaType(AndroidConstants.INTENT), context.copy, isNull_ = false)
    result += new RFAFact(intentSlot, intentValue)
//    val entSlot = FieldSlot(intentValue, "entries")
//    val entValue = PTATupleInstance(PTAPointStringInstance(context.copy), PTAPointStringInstance(context.copy), context.copy)
//    result += RFAFact(entSlot, entValue)
    val mComponentSlot = FieldSlot(intentValue, AndroidConstants.INTENT_COMPONENT)
    val mComponentValue = PTAInstance(new JawaType(AndroidConstants.COMPONENTNAME).toUnknown, context.copy, isNull_ = false)
    result += new RFAFact(mComponentSlot, mComponentValue)
    val mActionSlot = FieldSlot(intentValue, AndroidConstants.INTENT_ACTION)
    val mActionValue = PTAPointStringInstance(context.copy)
    result += new RFAFact(mActionSlot, mActionValue)
    val mCategoriesSlot = FieldSlot(intentValue, AndroidConstants.INTENT_CATEGORIES)
    val mCategoriesValue = PTAPointStringInstance(context.copy)
    result += new RFAFact(mCategoriesSlot, mCategoriesValue)
    val mTypeSlot = FieldSlot(intentValue, AndroidConstants.INTENT_MTYPE)
    val mTypeValue = PTAPointStringInstance(context.copy)
    result += new RFAFact(mTypeSlot, mTypeValue)
    val mDataSlot = FieldSlot(intentValue, AndroidConstants.INTENT_URI_DATA)
    val mDataValue = PTAPointStringInstance(context.copy)
    result += new RFAFact(mDataSlot, mDataValue)
    val mExtrasSlot = FieldSlot(intentValue, AndroidConstants.INTENT_EXTRAS)
    val mExtrasValue = PTATupleInstance(PTAPointStringInstance(context.copy), PTAInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown, context.copy, isNull_ = false), context.copy)
    result += new RFAFact(mExtrasSlot, mExtrasValue)
    result
  }
}
