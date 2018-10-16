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
  * Created by fgwei on 6/15/17.
  */
class StringSuTest extends SuTestBase("String.safsu") {
  "Ljava/lang/String;.<clinit>:()V" with_input () produce ()

  "Ljava/lang/String;.<init>:()V" with_input RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)) produce
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext))

  "Ljava/lang/String;.<init>:(II[C)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v3"), PTAInstance(new JawaType("char[]"), defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v3"), PTAInstance(new JawaType("char[]"), defContext2))
  )

  "Ljava/lang/String;.<init>:(Ljava/lang/String;)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/lang/String;.<init>:(Ljava/lang/String;C)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/lang/String;.<init>:(Ljava/lang/String;I)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/lang/String;.<init>:(Ljava/lang/String;Ljava/lang/String;)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    RFAFact(VarSlot("v0"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/lang/String;.<init>:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(VarSlot("v3"), PTAConcreteStringInstance("String", defContext4))
  ) produce (
    RFAFact(VarSlot("v0"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext3)),
    RFAFact(VarSlot("v3"), PTAConcreteStringInstance("String", defContext4))
  )

  "Ljava/lang/String;.<init>:(Ljava/lang/StringBuffer;)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.lang.StringBuffer"), defContext2)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.lang.StringBuffer"), defContext2), "value"), PTAConcreteStringInstance("Field", defContext3))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("Field", defContext3)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.lang.StringBuffer"), defContext2)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.lang.StringBuffer"), defContext2), "value"), PTAConcreteStringInstance("Field", defContext3))
  )

  "Ljava/lang/String;.<init>:(Ljava/lang/StringBuilder;)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.lang.StringBuilder"), defContext2)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.lang.StringBuilder"), defContext2), "value"), PTAConcreteStringInstance("Field", defContext3))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("Field", defContext3)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.lang.StringBuilder"), defContext2)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.lang.StringBuilder"), defContext2), "value"), PTAConcreteStringInstance("Field", defContext3))
  )

  "Ljava/lang/String;.<init>:([B)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("byte[]"), defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("byte[]"), defContext2))
  )

  "Ljava/lang/String;.<init>:([BI)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("byte[]"), defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("byte[]"), defContext2))
  )

  "Ljava/lang/String;.<init>:([BII)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("byte[]"), defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("byte[]"), defContext2))
  )

  "Ljava/lang/String;.<init>:([BIII)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("byte[]"), defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("byte[]"), defContext2))
  )

  "Ljava/lang/String;.<init>:([BIILjava/lang/String;)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("byte[]"), defContext2)),
    RFAFact(VarSlot("v4"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    RFAFact(VarSlot("v0"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("byte[]"), defContext2)),
    RFAFact(VarSlot("v4"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/lang/String;.<init>:([BIILjava/nio/charset/Charset;)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("byte[]"), defContext2)),
    RFAFact(VarSlot("v4"), PTAInstance(new JawaType("java.nio.charset.Charset"), defContext3))
  ) produce (
    RFAFact(VarSlot("v0"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("byte[]"), defContext2)),
    RFAFact(VarSlot("v4"), PTAInstance(new JawaType("java.nio.charset.Charset"), defContext3))
  )

  "Ljava/lang/String;.<init>:([BLjava/lang/String;)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("byte[]"), defContext2)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    RFAFact(VarSlot("v0"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("byte[]"), defContext2)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/lang/String;.<init>:([BLjava/nio/charset/Charset;)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("byte[]"), defContext2)),
    RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.nio.charset.Charset"), defContext3))
  ) produce (
    RFAFact(VarSlot("v0"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("byte[]"), defContext2)),
    RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.nio.charset.Charset"), defContext3))
  )

  "Ljava/lang/String;.<init>:([C)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("char[]"), defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("char[]"), defContext2))
  )

  "Ljava/lang/String;.<init>:([CII)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("char[]"), defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("char[]"), defContext2))
  )

  "Ljava/lang/String;.<init>:([III)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("", defContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("int[]"), defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("int[]"), defContext2))
  )

  "Ljava/lang/String;.copyValueOf:([C)Ljava/lang/String;" with_input (
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("char[]"), defContext2))
  ) produce (
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("char[]"), defContext2))
  )

  "Ljava/lang/String;.copyValueOf:([CII)Ljava/lang/String;" with_input (
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("char[]"), defContext2))
  ) produce (
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("char[]"), defContext2))
  )

  "Ljava/lang/String;.failedBoundsCheck:(III)Ljava/lang/StringIndexOutOfBoundsException;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.StringIndexOutOfBoundsException"), currentContext))
  )

  "Ljava/lang/String;.fastIndexOf:(II)I" with_input () produce ()

  "Ljava/lang/String;.foldCase:(C)C" with_input () produce ()

  "Ljava/lang/String;.format:(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.lang.Object[]"), defContext3))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v2"), PTAInstance(new JawaType("java.lang.Object[]"), defContext3)),
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/String;.format:(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.Locale"), defContext)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v3"), PTAInstance(new JawaType("java.lang.Object[]"), defContext3))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v1"), PTAInstance(new JawaType("java.util.Locale"), defContext)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v3"), PTAInstance(new JawaType("java.lang.Object[]"), defContext3)),
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/String;.indexAndLength:(I)Ljava/lang/StringIndexOutOfBoundsException;" with_input RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.StringIndexOutOfBoundsException"), currentContext))
  )

  "Ljava/lang/String;.indexOf:(Ljava/lang/String;Ljava/lang/String;IIC)I" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext3))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("String", defContext3))
  )

  "Ljava/lang/String;.indexOfSupplementary:(II)I" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/lang/String;.lastIndexOfSupplementary:(II)I" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/lang/String;.startEndAndLength:(II)Ljava/lang/StringIndexOutOfBoundsException;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.lang.StringIndexOutOfBoundsException"), currentContext))
  )

  "Ljava/lang/String;.valueOf:(C)Ljava/lang/String;" with_input () produce RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))

  "Ljava/lang/String;.valueOf:(D)Ljava/lang/String;" with_input () produce RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))

  "Ljava/lang/String;.valueOf:(F)Ljava/lang/String;" with_input () produce RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))

  "Ljava/lang/String;.valueOf:(I)Ljava/lang/String;" with_input () produce RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))

  "Ljava/lang/String;.valueOf:(J)Ljava/lang/String;" with_input () produce RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))

  "Ljava/lang/String;.valueOf:(Ljava/lang/Object;)Ljava/lang/String;" with_input () produce RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))

  "Ljava/lang/String;.valueOf:(Z)Ljava/lang/String;" with_input () produce RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))

  "Ljava/lang/String;.valueOf:([C)Ljava/lang/String;" with_input () produce RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))

  "Ljava/lang/String;.valueOf:([CII)Ljava/lang/String;" with_input () produce RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))

  "Ljava/lang/String;._getChars:(II[CI)V" with_input () produce ()

  "Ljava/lang/String;.charAt:(I)C" with_input () produce ()

  "Ljava/lang/String;.codePointAt:(I)I" with_input () produce ()

  "Ljava/lang/String;.codePointBefore:(I)I" with_input () produce ()

  "Ljava/lang/String;.codePointCount:(II)I" with_input () produce ()

  "Ljava/lang/String;.compareTo:(Ljava/lang/Object;)I" with_input () produce ()

  "Ljava/lang/String;.compareTo:(Ljava/lang/String;)I" with_input () produce ()

  "Ljava/lang/String;.compareToIgnoreCase:(Ljava/lang/String;)I" with_input () produce ()

  "Ljava/lang/String;.concat:(Ljava/lang/String;)Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/String;.contains:(Ljava/lang/CharSequence;)Z" with_input () produce ()

  "Ljava/lang/String;.contentEquals:(Ljava/lang/CharSequence;)Z" with_input () produce ()

  "Ljava/lang/String;.contentEquals:(Ljava/lang/StringBuffer;)Z" with_input () produce ()

  "Ljava/lang/String;.endsWith:(Ljava/lang/String;)Z" with_input () produce ()

  "Ljava/lang/String;.equals:(Ljava/lang/Object;)Z" with_input () produce ()

  "Ljava/lang/String;.equalsIgnoreCase:(Ljava/lang/String;)Z" with_input () produce ()

  "Ljava/lang/String;.getBytes:(II[BI)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v3"), PTAInstance(new JawaType("byte", 1), currentContext))
  )

  "Ljava/lang/String;.getBytes:()[B" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("byte", 1), currentContext))
  )

  "Ljava/lang/String;.getBytes:(Ljava/lang/String;)[B" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("byte", 1), currentContext))
  )

  "Ljava/lang/String;.getBytes:(Ljava/nio/charset/Charset;)[B" with_input
    RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.nio.charset.Charset"), defContext)) produce (
    RFAFact(VarSlot("v0"), PTAInstance(new JawaType("java.nio.charset.Charset"), defContext)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("byte", 1), currentContext))
  )

  "Ljava/lang/String;.getChars:(II[CI)V" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("v3"), PTAInstance(new JawaType("char", 1), currentContext))
  )

  "Ljava/lang/String;.hashCode:()I" with_input () produce ()

  "Ljava/lang/String;.indexOf:(I)I" with_input () produce ()

  "Ljava/lang/String;.indexOf:(II)I" with_input () produce ()

  "Ljava/lang/String;.indexOf:(Ljava/lang/String;)I" with_input () produce ()

  "Ljava/lang/String;.indexOf:(Ljava/lang/String;I)I" with_input () produce ()

  "Ljava/lang/String;.intern:()Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext2))
  )
  "Ljava/lang/String;.isEmpty:()Z" with_input () produce ()

  "Ljava/lang/String;.lastIndexOf:(I)I" with_input () produce ()

  "Ljava/lang/String;.lastIndexOf:(II)I" with_input () produce ()

  "Ljava/lang/String;.lastIndexOf:(Ljava/lang/String;)I" with_input () produce ()

  "Ljava/lang/String;.lastIndexOf:(Ljava/lang/String;I)I" with_input () produce ()

  "Ljava/lang/String;.length:()I" with_input () produce ()

  "Ljava/lang/String;.matches:(Ljava/lang/String;)Z" with_input () produce ()

  "Ljava/lang/String;.offsetByCodePoints:(II)I" with_input () produce ()

  "Ljava/lang/String;.regionMatches:(ILjava/lang/String;II)Z" with_input () produce ()

  "Ljava/lang/String;.regionMatches:(ZILjava/lang/String;II)Z" with_input () produce ()

  "Ljava/lang/String;.replace:(CC)Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/String;.replace:(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/String;.replaceAll:(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/String;.replaceFirst:(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/String;.split:(Ljava/lang/String;)[Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/String;.split:(Ljava/lang/String;I)[Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/String;.startsWith:(Ljava/lang/String;)Z" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/lang/String;.startsWith:(Ljava/lang/String;I)Z" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/lang/String;.subSequence:(II)Ljava/lang/CharSequence;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/String;.substring:(I)Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/String;.substring:(II)Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Ljava/lang/String;.toCharArray:()[C" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("char", 1), currentContext))
  )

  "Ljava/lang/String;.toLowerCase:()Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/lang/String;.toLowerCase:(Ljava/util/Locale;)Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/lang/String;.toString:()Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/lang/String;.toUpperCase:()Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/lang/String;.toUpperCase:(Ljava/util/Locale;)Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext2))
  )

  "Ljava/lang/String;.trim:()Ljava/lang/String;" with_input (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2))
  ) produce (
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("v0"), PTAConcreteStringInstance("String", defContext2)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("String", defContext2))
  )
}
