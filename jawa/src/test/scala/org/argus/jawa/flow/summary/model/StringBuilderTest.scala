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
  * Created by fgwei on 6/22/17.
  */
class StringBuilderTest extends SuTestBase("StringBuilder.safsu") {

  val thisInstance = PTAInstance(new JawaType("java.lang.StringBuilder"), defContext)
  val thisFact = RFAFact(VarSlot("v0"), thisInstance)
  val thisValueInstance = PTAConcreteStringInstance("StringBuilder", defContext)
  val thisValueFact = RFAFact(FieldSlot(thisInstance, "value"), thisValueInstance)

  "Ljava/lang/StringBuilder;.<init>:()V" with_input thisFact produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/StringBuilder;.<init>:(I)V" with_input thisFact produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/StringBuilder;.<init>:(Ljava/lang/CharSequence;)V" with_input (
    thisFact,
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("NewString", defContext2))
  ) produce (
    thisFact,
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("NewString", defContext2)),
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/StringBuilder;.<init>:(Ljava/lang/String;)V" with_input (
    thisFact,
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("NewString", defContext2))
  ) produce (
    thisFact,
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("NewString", defContext2)),
    RFAFact(FieldSlot(thisInstance, "value"), PTAConcreteStringInstance("NewString", defContext2))
  )

  "Ljava/lang/StringBuilder;.append:(C)Ljava/lang/Appendable;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.append:(C)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.append:(D)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.append:(F)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.append:(I)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.append:(J)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.append:(Ljava/lang/CharSequence;)Ljava/lang/Appendable;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.append:(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.append:(Ljava/lang/CharSequence;II)Ljava/lang/Appendable;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.append:(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.append:(Ljava/lang/Object;)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact,
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("string", currentContext))
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAConcreteStringInstance("string", currentContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("string", currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.append:(Ljava/lang/StringBuffer;)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.append:(Z)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.append:([C)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.append:([CII)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.appendCodePoint:(I)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.capacity:()I" with_input () produce ()

  "Ljava/lang/StringBuilder;.charAt:(I)C" with_input () produce ()

  "Ljava/lang/StringBuilder;.codePointAt:(I)I" with_input () produce ()

  "Ljava/lang/StringBuilder;.codePointBefore:(I)I" with_input () produce ()

  "Ljava/lang/StringBuilder;.codePointCount:(II)I" with_input () produce ()

  "Ljava/lang/StringBuilder;.delete:(II)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.deleteCharAt:(I)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.ensureCapacity:(I)V" with_input () produce ()

  "Ljava/lang/StringBuilder;.getChars:(II[CI)V" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(VarSlot("v3"), PTAInstance(new JawaType("char", 1), currentContext))
  )

  "Ljava/lang/StringBuilder;.indexOf:(Ljava/lang/String;)I" with_input () produce ()

  "Ljava/lang/StringBuilder;.indexOf:(Ljava/lang/String;I)I" with_input () produce ()

  "Ljava/lang/StringBuilder;.insert:(IC)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.insert:(ID)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.insert:(IF)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.insert:(II)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.insert:(IJ)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.insert:(ILjava/lang/CharSequence;)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.insert:(ILjava/lang/CharSequence;II)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.insert:(ILjava/lang/Object;)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.insert:(ILjava/lang/String;)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.insert:(IZ)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.insert:(I[C)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.insert:(I[CII)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.lastIndexOf:(Ljava/lang/String;)I" with_input () produce ()

  "Ljava/lang/StringBuilder;.lastIndexOf:(Ljava/lang/String;I)I" with_input () produce ()

  "Ljava/lang/StringBuilder;.length:()I" with_input () produce ()

  "Ljava/lang/StringBuilder;.offsetByCodePoints:(II)I" with_input () produce ()

  "Ljava/lang/StringBuilder;.replace:(IILjava/lang/String;)Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.reverse:()Ljava/lang/StringBuilder;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Ljava/lang/StringBuilder;.setCharAt:(IC)V" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/StringBuilder;.setLength:(I)V" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "value"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/StringBuilder;.subSequence:(II)Ljava/lang/CharSequence;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/StringBuilder;.substring:(I)Ljava/lang/String;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/StringBuilder;.substring:(II)Ljava/lang/String;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/StringBuilder;.toString:()Ljava/lang/String;" with_input (
    thisFact,
    thisValueFact
  ) produce (
    thisFact,
    thisValueFact,
    RFAFact(VarSlot("temp"), thisValueInstance)
  )

  "Ljava/lang/StringBuilder;.trimToSize:()V" with_input () produce ()
}
