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
class IntentFilterSuTest extends SuTestBase("IntentFilter.safsu") {

  val thisInstance = PTAInstance(new JawaType(AndroidConstants.INTENT_FILTER), defContext)
  val thisFact = RFAFact(VarSlot("v0"), thisInstance)
  val thisMActionsInstance = PTAConcreteStringInstance("my.Action", defContext)
  val thisMActionsFact = RFAFact(FieldSlot(thisInstance, "mActions"), thisMActionsInstance)
  val thisMCategoriesInstance = PTAConcreteStringInstance("my.Category", defContext)
  val thisMCategoriesFact = RFAFact(FieldSlot(thisInstance, "mCategories"), thisMCategoriesInstance)
  val thisMTypeInstance = PTAConcreteStringInstance("my.Type", defContext)
  val thisMTypeFact = RFAFact(FieldSlot(thisInstance, "mType"), thisMTypeInstance)
  val thisMDataInstance = PTAInstance(new JawaType(AndroidConstants.URI), defContext)
  val thisMDataFact = RFAFact(FieldSlot(thisInstance, "mData"), thisMDataInstance)

  "Landroid/content/IntentFilter;.<clinit>:()V" with_input () produce ()

  "Landroid/content/IntentFilter;.<init>:()V" with_input thisFact produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "mData"), PTAInstance(new JawaType(AndroidConstants.URI), currentContext))
  )

  "Landroid/content/IntentFilter;.<init>:(Landroid/content/IntentFilter;)V" with_input thisFact produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "mData"), PTAInstance(new JawaType(AndroidConstants.URI), currentContext))
  )

  "Landroid/content/IntentFilter;.<init>:(Ljava/lang/String;)V" with_input (
    thisFact,
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Action", defContext2))
  ) produce (
    thisFact,
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Action", defContext2)),
    RFAFact(FieldSlot(thisInstance, "mActions"), PTAConcreteStringInstance("my.Action", defContext2)),
    RFAFact(FieldSlot(thisInstance, "mData"), PTAInstance(new JawaType(AndroidConstants.URI), currentContext))
  )

  "Landroid/content/IntentFilter;.<init>:(Ljava/lang/String;Ljava/lang/String;)V" with_input (
    thisFact,
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Action", defContext2)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("my.Type", defContext3))
  ) produce (
    thisFact,
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Action", defContext2)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("my.Type", defContext3)),
    RFAFact(FieldSlot(thisInstance, "mActions"), PTAConcreteStringInstance("my.Action", defContext2)),
    RFAFact(FieldSlot(thisInstance, "mType"), PTAConcreteStringInstance("my.Type", defContext3)),
    RFAFact(FieldSlot(thisInstance, "mData"), PTAInstance(new JawaType(AndroidConstants.URI), currentContext))
  )

  "Landroid/content/IntentFilter;.actionsIterator:()Ljava/util/Iterator;" with_input (
    thisFact,
    thisMActionsFact,
    thisMCategoriesFact,
    thisMTypeFact,
    thisMDataFact
  ) produce (
    thisFact,
    thisMActionsFact,
    thisMCategoriesFact,
    thisMTypeFact,
    thisMDataFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.ArrayList"), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.ArrayList"), currentContext), "items"), thisMActionsInstance)
  )

  "Landroid/content/IntentFilter;.addAction:(Ljava/lang/String;)V" with_input (
    thisFact,
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Action", defContext2))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "mActions"), PTAConcreteStringInstance("my.Action", defContext2)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Action", defContext2))
  )

  "Landroid/content/IntentFilter;.addCategory:(Ljava/lang/String;)V" with_input (
    thisFact,
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Category", defContext2))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "mCategories"), PTAConcreteStringInstance("my.Category", defContext2)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Category", defContext2))
  )

  "Landroid/content/IntentFilter;.addDataAuthority:(Ljava/lang/String;Ljava/lang/String;)V" with_input (
    thisFact,
    thisMDataFact,
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Host", defContext2)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("0521", defContext3))
  ) produce (
    thisFact,
    thisMDataFact,
    RFAFact(FieldSlot(thisMDataInstance, "host"), PTAConcreteStringInstance("my.Host", defContext2)),
    RFAFact(FieldSlot(thisMDataInstance, "port"), PTAConcreteStringInstance("0521", defContext3)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Host", defContext2)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("0521", defContext3))
  )

  "Landroid/content/IntentFilter;.addDataPath:(Ljava/lang/String;I)V" with_input (
    thisFact,
    thisMDataFact,
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Path", defContext2))
  ) produce (
    thisFact,
    thisMDataFact,
    RFAFact(FieldSlot(thisMDataInstance, "path"), PTAConcreteStringInstance("my.Path", defContext2)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Path", defContext2))
  )

  "Landroid/content/IntentFilter;.addDataScheme:(Ljava/lang/String;)V" with_input (
    thisFact,
    thisMDataFact,
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Scheme", defContext2))
  ) produce (
    thisFact,
    thisMDataFact,
    RFAFact(FieldSlot(thisMDataInstance, "scheme"), PTAConcreteStringInstance("my.Scheme", defContext2)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Scheme", defContext2))
  )

  "Landroid/content/IntentFilter;.addDataType:(Ljava/lang/String;)V" with_input (
    thisFact,
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Type", defContext2))
  ) produce (
    thisFact,
    RFAFact(FieldSlot(thisInstance, "mType"), PTAConcreteStringInstance("my.Type", defContext2)),
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Type", defContext2))
  )

  "Landroid/content/IntentFilter;.authoritiesIterator:()Ljava/util/Iterator;" with_input (
    thisFact,
    thisMDataFact,
    RFAFact(FieldSlot(thisMDataInstance, "host"), PTAConcreteStringInstance("my.Host", defContext2)),
    RFAFact(FieldSlot(thisMDataInstance, "port"), PTAConcreteStringInstance("0521", defContext3))
  ) produce (
    thisFact,
    thisMDataFact,
    RFAFact(FieldSlot(thisMDataInstance, "host"), PTAConcreteStringInstance("my.Host", defContext2)),
    RFAFact(FieldSlot(thisMDataInstance, "port"), PTAConcreteStringInstance("0521", defContext3)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.ArrayList"), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.ArrayList"), currentContext), "items"), PTAConcreteStringInstance("my.Host", defContext2))
  )

  "Landroid/content/IntentFilter;.categoriesIterator:()Ljava/util/Iterator;" with_input (
    thisFact,
    thisMActionsFact,
    thisMCategoriesFact,
    thisMTypeFact,
    thisMDataFact
  ) produce (
    thisFact,
    thisMActionsFact,
    thisMCategoriesFact,
    thisMTypeFact,
    thisMDataFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.ArrayList"), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.ArrayList"), currentContext), "items"), thisMCategoriesInstance)
  )

  "Landroid/content/IntentFilter;.countActions:()I" with_input () produce ()

  "Landroid/content/IntentFilter;.countCategories:()I" with_input () produce ()

  "Landroid/content/IntentFilter;.countDataAuthorities:()I" with_input () produce ()

  "Landroid/content/IntentFilter;.countDataPaths:()I" with_input () produce ()

  "Landroid/content/IntentFilter;.countDataSchemes:()I" with_input () produce ()

  "Landroid/content/IntentFilter;.countDataTypes:()I" with_input () produce ()

  "Landroid/content/IntentFilter;.create:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/IntentFilter;" with_input (
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Action", defContext2)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("my.Type", defContext3))
  ) produce (
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("my.Action", defContext2)),
    RFAFact(VarSlot("v2"), PTAConcreteStringInstance("my.Type", defContext3)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("android.content.IntentFilter"), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("android.content.IntentFilter"), currentContext), "mActions"), PTAConcreteStringInstance("my.Action", defContext2)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("android.content.IntentFilter"), currentContext), "mType"), PTAConcreteStringInstance("my.Type", defContext3)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("android.content.IntentFilter"), currentContext), "mData"), PTAInstance(new JawaType("android.net.Uri"), currentContext))
  )

  "Landroid/content/IntentFilter;.debugCheck:()Z" with_input () produce ()

  "Landroid/content/IntentFilter;.describeContents:()I" with_input () produce ()

  "Landroid/content/IntentFilter;.dump:(Landroid/util/Printer;Ljava/lang/String;)V" with_input () produce ()

  "Landroid/content/IntentFilter;.getAction:(I)Ljava/lang/String;" with_input (
    thisFact,
    thisMActionsFact,
    thisMCategoriesFact,
    thisMTypeFact,
    thisMDataFact
  ) produce (
    thisFact,
    thisMActionsFact,
    thisMCategoriesFact,
    thisMTypeFact,
    thisMDataFact,
    RFAFact(VarSlot("temp"), thisMActionsInstance)
  )

  "Landroid/content/IntentFilter;.getCategory:(I)Ljava/lang/String;" with_input (
    thisFact,
    thisMActionsFact,
    thisMCategoriesFact,
    thisMTypeFact,
    thisMDataFact
  ) produce (
    thisFact,
    thisMActionsFact,
    thisMCategoriesFact,
    thisMTypeFact,
    thisMDataFact,
    RFAFact(VarSlot("temp"), thisMCategoriesInstance)
  )

  "Landroid/content/IntentFilter;.getDataAuthority:(I)Landroid/content/IntentFilter$AuthorityEntry;" with_input (
    thisFact,
    thisMDataFact
  ) produce (
    thisFact,
    thisMDataFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("android.content.IntentFilter$AuthorityEntry"), currentContext))
  )

  "Landroid/content/IntentFilter;.getDataPath:(I)Landroid/os/PatternMatcher;" with_input (
    thisFact,
    thisMDataFact
  ) produce (
    thisFact,
    thisMDataFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("android.os.PatternMatcher"), currentContext))
  )

  "Landroid/content/IntentFilter;.getDataScheme:(I)Ljava/lang/String;" with_input (
    thisFact,
    thisMDataFact,
    RFAFact(FieldSlot(thisMDataInstance, "scheme"), PTAConcreteStringInstance("my.Scheme", defContext2))
  ) produce (
    thisFact,
    thisMDataFact,
    RFAFact(FieldSlot(thisMDataInstance, "scheme"), PTAConcreteStringInstance("my.Scheme", defContext2)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("my.Scheme", defContext2))
  )

  "Landroid/content/IntentFilter;.getDataType:(I)Ljava/lang/String;" with_input (
    thisFact,
    thisMActionsFact,
    thisMCategoriesFact,
    thisMTypeFact,
    thisMDataFact
  ) produce (
    thisFact,
    thisMActionsFact,
    thisMCategoriesFact,
    thisMTypeFact,
    thisMDataFact,
    RFAFact(VarSlot("temp"), thisMTypeInstance)
  )

  "Landroid/content/IntentFilter;.getPriority:()I" with_input () produce ()

  "Landroid/content/IntentFilter;.hasAction:(Ljava/lang/String;)Z" with_input () produce ()

  "Landroid/content/IntentFilter;.hasCategory:(Ljava/lang/String;)Z" with_input () produce ()

  "Landroid/content/IntentFilter;.hasDataAuthority:(Landroid/net/Uri;)Z" with_input () produce ()

  "Landroid/content/IntentFilter;.hasDataPath:(Ljava/lang/String;)Z" with_input () produce ()

  "Landroid/content/IntentFilter;.hasDataScheme:(Ljava/lang/String;)Z" with_input () produce ()

  "Landroid/content/IntentFilter;.hasDataType:(Ljava/lang/String;)Z" with_input () produce ()

  "Landroid/content/IntentFilter;.match:(Landroid/content/ContentResolver;Landroid/content/Intent;ZLjava/lang/String;)I" with_input () produce ()

  "Landroid/content/IntentFilter;.match:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/net/Uri;Ljava/util/Set;Ljava/lang/String;)I" with_input () produce ()

  "Landroid/content/IntentFilter;.matchAction:(Ljava/lang/String;)Z" with_input () produce ()

  "Landroid/content/IntentFilter;.matchCategories:(Ljava/util/Set;)Ljava/lang/String;" with_input () produce ()

  "Landroid/content/IntentFilter;.matchData:(Ljava/lang/String;Ljava/lang/String;Landroid/net/Uri;)I" with_input () produce ()

  "Landroid/content/IntentFilter;.matchDataAuthority:(Landroid/net/Uri;)I" with_input () produce ()

  "Landroid/content/IntentFilter;.pathsIterator:()Ljava/util/Iterator;" with_input (
    thisFact,
    thisMDataFact,
    RFAFact(FieldSlot(thisMDataInstance, "path"), PTAConcreteStringInstance("my.Path", defContext2))
  ) produce (
    thisFact,
    thisMDataFact,
    RFAFact(FieldSlot(thisMDataInstance, "path"), PTAConcreteStringInstance("my.Path", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.ArrayList"), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.ArrayList"), currentContext), "items"), PTAConcreteStringInstance("my.Path", defContext2))
  )

  "Landroid/content/IntentFilter;.readFromXml:(Lorg/xmlpull/v1/XmlPullParser;)V" with_input () produce ()

  "Landroid/content/IntentFilter;.schemesIterator:()Ljava/util/Iterator;" with_input (
    thisFact,
    thisMDataFact,
    RFAFact(FieldSlot(thisMDataInstance, "scheme"), PTAConcreteStringInstance("my.Scheme", defContext2))
  ) produce (
    thisFact,
    thisMDataFact,
    RFAFact(FieldSlot(thisMDataInstance, "scheme"), PTAConcreteStringInstance("my.Scheme", defContext2)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.ArrayList"), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.ArrayList"), currentContext), "items"), PTAConcreteStringInstance("my.Scheme", defContext2))
  )

  "Landroid/content/IntentFilter;.setPriority:(I)V" with_input () produce ()

  "Landroid/content/IntentFilter;.typesIterator:()Ljava/util/Iterator;" with_input (
    thisFact,
    thisMActionsFact,
    thisMCategoriesFact,
    thisMTypeFact,
    thisMDataFact
  ) produce (
    thisFact,
    thisMActionsFact,
    thisMCategoriesFact,
    thisMTypeFact,
    thisMDataFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.ArrayList"), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.ArrayList"), currentContext), "items"), thisMTypeInstance)
  )

  "Landroid/content/IntentFilter;.writeToParcel:(Landroid/os/Parcel;I)V" with_input () produce ()

  "Landroid/content/IntentFilter;.writeToXml:(Lorg/xmlpull/v1/XmlSerializer;)V" with_input () produce ()
}
