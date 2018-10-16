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
import org.argus.jawa.core.elements.JawaType
import org.argus.jawa.flow.pta._
import org.argus.jawa.flow.pta.rfa.RFAFact

/**
  * Created by fgwei on 6/24/17.
  */
class UriSuTest extends SuTestBase("Uri.safsu") {

  val thisInstance = PTAInstance(new JawaType(AndroidConstants.URI), defContext)
  val thisFact = RFAFact(VarSlot("v0"), thisInstance)
  val thisUriInstance = PTAConcreteStringInstance("content://org.arguslab", defContext)
  val thisUriFact = RFAFact(FieldSlot(thisInstance, "uri"), thisUriInstance)

  "Landroid/net/Uri;.<clinit>:()V" with_input () produce ()

  "Landroid/net/Uri;.buildUpon:()Landroid/net/Uri$Builder;" with_input (
    thisFact,
    thisUriFact
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("android.net.Uri$Builder"), currentContext))
  )

  "Landroid/net/Uri;.compareTo:(Landroid/net/Uri;)I" with_input () produce ()

  "Landroid/net/Uri;.compareTo:(Ljava/lang/Object;)I" with_input () produce ()

  "Landroid/net/Uri;.decode:(Ljava/lang/String;)Ljava/lang/String;" with_input RFAFact(VarSlot("v1"), PTAConcreteStringInstance("content://org.hugo", defContext2)) produce (
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("content://org.hugo", defContext2)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("content://org.hugo", defContext2))
  )

  "Landroid/net/Uri;.encode:(Ljava/lang/String;)Ljava/lang/String;" with_input RFAFact(VarSlot("v1"), PTAConcreteStringInstance("content://org.hugo", defContext2)) produce (
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("content://org.hugo", defContext2)),
    RFAFact(VarSlot("temp"), PTAConcreteStringInstance("content://org.hugo", defContext2))
  )

  "Landroid/net/Uri;.encode:(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" with_input () produce RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))

  "Landroid/net/Uri;.equals:(Ljava/lang/Object;)Z" with_input () produce ()

  "Landroid/net/Uri;.fromFile:(Ljava/io/File;)Landroid/net/Uri;" with_input () produce (
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType(AndroidConstants.URI), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType(AndroidConstants.URI), currentContext), "uri"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.fromParts:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri;" with_input () produce (
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType(AndroidConstants.URI), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType(AndroidConstants.URI), currentContext), "uri"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getAuthority:()Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getBooleanQueryParameter:(Ljava/lang/String;Z)Z" with_input () produce ()

  "Landroid/net/Uri;.getCanonicalUri:()Landroid/net/Uri;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), thisInstance),
  )

  "Landroid/net/Uri;.getEncodedAuthority:()Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getEncodedFragment:()Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getEncodedPath:()Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getEncodedQuery:()Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getEncodedSchemeSpecificPart:()Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getEncodedUserInfo:()Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getFragment:()Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getHost:()Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getLastPathSegment:()Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getPath:()Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getPathSegments:()Ljava/util/List;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getPort:()I" with_input () produce ()

  "Landroid/net/Uri;.getQuery:()Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getQueryParameter:(Ljava/lang/String;)Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getQueryParameterNames:()Ljava/util/Set;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.HashSet"), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.HashSet"), currentContext), "items"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getQueryParameters:(Ljava/lang/String;)Ljava/util/List;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType("java.util.ArrayList"), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType("java.util.ArrayList"), currentContext), "items"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getScheme:()Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getSchemeSpecificPart:()Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.getUserInfo:()Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.hashCode:()I" with_input () produce ()

  "Landroid/net/Uri;.isAbsolute:()Z" with_input () produce ()

  "Landroid/net/Uri;.isAllowed:(CLjava/lang/String;)Z" with_input () produce ()

  "Landroid/net/Uri;.isHierarchical:()Z" with_input () produce ()

  "Landroid/net/Uri;.isOpaque:()Z" with_input () produce ()

  "Landroid/net/Uri;.isRelative:()Z" with_input () produce ()

  "Landroid/net/Uri;.normalizeScheme:()Landroid/net/Uri;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), thisInstance)
  )

  "Landroid/net/Uri;.parse:(Ljava/lang/String;)Landroid/net/Uri;" with_input RFAFact(VarSlot("v1"), PTAConcreteStringInstance("content://org.hugo", defContext)) produce (
    RFAFact(VarSlot("v1"), PTAConcreteStringInstance("content://org.hugo", defContext)),
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType(AndroidConstants.URI), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType(AndroidConstants.URI), currentContext), "uri"), PTAConcreteStringInstance("content://org.hugo", defContext))
  )

  "Landroid/net/Uri;.toSafeString:()Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), thisUriInstance)
  )

  "Landroid/net/Uri;.toString:()Ljava/lang/String;" with_input (
    thisFact,
    thisUriFact,
  ) produce (
    thisFact,
    thisUriFact,
    RFAFact(VarSlot("temp"), thisUriInstance)
  )

  "Landroid/net/Uri;.withAppendedPath:(Landroid/net/Uri;Ljava/lang/String;)Landroid/net/Uri;" with_input () produce (
    RFAFact(VarSlot("temp"), PTAInstance(new JawaType(AndroidConstants.URI), currentContext)),
    RFAFact(FieldSlot(PTAInstance(new JawaType(AndroidConstants.URI), currentContext), "uri"), PTAPointStringInstance(currentContext))
  )

  "Landroid/net/Uri;.writeToParcel:(Landroid/os/Parcel;Landroid/net/Uri;)V" with_input () produce ()

}
