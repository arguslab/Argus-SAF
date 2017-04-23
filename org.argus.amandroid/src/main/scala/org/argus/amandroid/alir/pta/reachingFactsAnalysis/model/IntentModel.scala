/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.pta.reachingFactsAnalysis.model

import org.argus.amandroid.core.AndroidConstants
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.pta.reachingFactsAnalysis.model.ModelCall
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, RFAFactFactory}
import org.argus.jawa.core._
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class IntentModel extends ModelCall {
  final val TITLE = "IntentModel"
  
  def isModelCall(p: JawaMethod): Boolean = p.getDeclaringClass.getName.equals(AndroidConstants.INTENT)
  
  def doModelCall(s: PTAResult, p: JawaMethod, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    var newFacts = isetEmpty[RFAFact]
    var delFacts = isetEmpty[RFAFact]
    var byPassFlag = true
    p.getSignature.signature match{
      case "Landroid/content/Intent;.<clinit>:()V" =>  //static constructor
      case "Landroid/content/Intent;.<init>:()V" =>  //public constructor
      case "Landroid/content/Intent;.<init>:(Landroid/content/Context;Ljava/lang/Class;)V" =>  //public constructor
        intentInitWithCC(p.getDeclaringClass.global, s, args, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.<init>:(Landroid/content/Intent;)V" =>  //public constructor
        intentInitWithIntent(s, args, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.<init>:(Landroid/content/Intent;Z)V" =>  //private constructor
        intentInitWithIntent(s, args, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.<init>:(Landroid/os/Parcel;)V" =>  //protected constructor
        //TODO:
      case "Landroid/content/Intent;.<init>:(Ljava/lang/String;)V" =>  //public constructor
        intentInitWithAction(s, args, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.<init>:(Ljava/lang/String;Landroid/net/Uri;)V" =>  //public constructor
        intentInitWithActionAndData(s, args, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.<init>:(Ljava/lang/String;Landroid/net/Uri;Landroid/content/Context;Ljava/lang/Class;)V" =>  //public constructor
        intentInitWithActionDataAndComponent(p.getDeclaringClass.global, s, args, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.addCategory:(Ljava/lang/String;)Landroid/content/Intent;" =>  //public
        intentAddCategory(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.addFlags:(I)Landroid/content/Intent;" =>  //public
      case "Landroid/content/Intent;.clone:()Ljava/lang/Object;" =>  //public
        intentClone(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.cloneFilter:()Landroid/content/Intent;" =>  //public
      case "Landroid/content/Intent;.createChooser:(Landroid/content/Intent;Ljava/lang/CharSequence;)Landroid/content/Intent;" =>  //public static
      case "Landroid/content/Intent;.describeContents:()I" =>  //public
      case "Landroid/content/Intent;.fillIn:(Landroid/content/Intent;I)I" =>  //public
      case "Landroid/content/Intent;.filterEquals:(Landroid/content/Intent;)Z" =>  //public
      case "Landroid/content/Intent;.filterHashCode:()I" =>  //public
      case "Landroid/content/Intent;.getAction:()Ljava/lang/String;" =>  //public
      case "Landroid/content/Intent;.getBooleanArrayExtra:(Ljava/lang/String;)[Z" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("boolean")) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getBooleanExtra:(Ljava/lang/String;Z)Z" =>  //public
        intentGetExtraWithDefault(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getBundleExtra:(Ljava/lang/String;)Landroid/os/Bundle;" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType(AndroidConstants.BUNDLE)) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getByteArrayExtra:(Ljava/lang/String;)[B" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("byte", 1)) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getByteExtra:(Ljava/lang/String;B)B" =>  //public
        intentGetExtraWithDefault(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getCategories:()Ljava/util/Set;" =>  //public
      case "Landroid/content/Intent;.getCharArrayExtra:(Ljava/lang/String;)[C" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("char", 1)) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getCharExtra:(Ljava/lang/String;C)C" =>  //public
        intentGetExtraWithDefault(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getCharSequenceArrayExtra:(Ljava/lang/String;)[Ljava/lang/CharSequence;" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("java.lang.CharSequence", 1)) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getCharSequenceArrayListExtra:(Ljava/lang/String;)Ljava/util/ArrayList;" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("java.util.ArrayList")) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getCharSequenceExtra:(Ljava/lang/String;)Ljava/lang/CharSequence;" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("java.lang.CharSequence")) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getClipData:()Landroid/content/ClipData;" =>  //public
      case "Landroid/content/Intent;.getComponent:()Landroid/content/ComponentName;" =>  //public
      case "Landroid/content/Intent;.getData:()Landroid/net/Uri;" =>  //public
      case "Landroid/content/Intent;.getDataString:()Ljava/lang/String;" =>  //public
      case "Landroid/content/Intent;.getDoubleArrayExtra:(Ljava/lang/String;)[D" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("double", 1)) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getDoubleExtra:(Ljava/lang/String;D)D" =>  //public
        intentGetExtraWithDefault(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getExtra:(Ljava/lang/String;)Ljava/lang/Object;" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("java.lang.Object")) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getExtra:(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;" =>  //public
        intentGetExtraWithDefault(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getExtras:()Landroid/os/Bundle;" =>  //public
        intentGetExtras(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getFlags:()I" =>  //public
      case "Landroid/content/Intent;.getFloatArrayExtra:(Ljava/lang/String;)[F" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("float", 1)) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getFloatExtra:(Ljava/lang/String;F)F" =>  //public
        intentGetExtraWithDefault(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getIBinderExtra:(Ljava/lang/String;)Landroid/os/IBinder;" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("android.os.Binder")) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getIntArrayExtra:(Ljava/lang/String;)[I" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("int", 1)) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getIntExtra:(Ljava/lang/String;I)I" =>  //public
        intentGetExtraWithDefault(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getIntegerArrayListExtra:(Ljava/lang/String;)Ljava/util/ArrayList;" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("java.lang.ArrayList")) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getIntent:(Ljava/lang/String;)Landroid/content/Intent;" =>  //public static
        intentGetExtra(s, args, retVar, currentContext, new JawaType("android.content.Intent")) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getIntentOld:(Ljava/lang/String;)Landroid/content/Intent;" =>  //public static
        intentGetExtra(s, args, retVar, currentContext, new JawaType("android.content.Intent")) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getLongArrayExtra:(Ljava/lang/String;)[J" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("long", 1)) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getLongExtra:(Ljava/lang/String;J)J" =>  //public
        intentGetExtraWithDefault(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getPackage:()Ljava/lang/String;" =>  //public
      case "Landroid/content/Intent;.getParcelableArrayExtra:(Ljava/lang/String;)[Landroid/os/Parcelable;" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("android.os.Parcelable", 1)) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getParcelableArrayListExtra:(Ljava/lang/String;)Ljava/util/ArrayList;" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("java.util.ArrayList")) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getParcelableExtra:(Ljava/lang/String;)Landroid/os/Parcelable;" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("android.os.Parcelable")) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getScheme:()Ljava/lang/String;" =>  //public
      case "Landroid/content/Intent;.getSelector:()Landroid/content/Intent;" =>  //public
      case "Landroid/content/Intent;.getSerializableExtra:(Ljava/lang/String;)Ljava/io/Serializable;" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("java.io.Serializable")) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getShortArrayExtra:(Ljava/lang/String;)[S" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("short", 1)) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getShortExtra:(Ljava/lang/String;S)S" =>  //public
        intentGetExtraWithDefault(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getSourceBounds:()Landroid/graphics/Rect;" =>  //public
      case "Landroid/content/Intent;.getStringArrayExtra:(Ljava/lang/String;)[Ljava/lang/String;" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("java.lang.String", 1)) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getStringArrayListExtra:(Ljava/lang/String;)Ljava/util/ArrayList;" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("java.util.ArrayList")) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getStringExtra:(Ljava/lang/String;)Ljava/lang/String;" =>  //public
        intentGetExtra(s, args, retVar, currentContext, new JawaType("java.lang.String")) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.getType:()Ljava/lang/String;" =>  //public
      case "Landroid/content/Intent;.hasCategory:(Ljava/lang/String;)Z" =>  //public
      case "Landroid/content/Intent;.hasExtra:(Ljava/lang/String;)Z" =>  //public
      case "Landroid/content/Intent;.hasFileDescriptors:()Z" =>  //public
      case "Landroid/content/Intent;.isExcludingStopped:()Z" =>  //public
      case "Landroid/content/Intent;.makeClipItem:(Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;I)Landroid/content/ClipData$Item;" =>  //private static
      case "Landroid/content/Intent;.makeMainActivity:(Landroid/content/ComponentName;)Landroid/content/Intent;" =>  //public static
      case "Landroid/content/Intent;.makeMainSelectorActivity:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;" =>  //public static
      case "Landroid/content/Intent;.makeRestartActivityTask:(Landroid/content/ComponentName;)Landroid/content/Intent;" =>  //public static
      case "Landroid/content/Intent;.migrateExtraStreamToClipData:()Z" =>  //public
      case "Landroid/content/Intent;.normalizeMimeType:(Ljava/lang/String;)Ljava/lang/String;" =>  //public static
      case "Landroid/content/Intent;.parseIntent:(Landroid/content/res/Resources;Lorg/xmlpull/v1/XmlPullParser;Landroid/util/AttributeSet;)Landroid/content/Intent;" =>  //public static
      case "Landroid/content/Intent;.parseUri:(Ljava/lang/String;I)Landroid/content/Intent;" =>  //public static
      case "Landroid/content/Intent;.putCharSequenceArrayListExtra:(Ljava/lang/String;Ljava/util/ArrayList;)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;B)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;C)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;D)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;F)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;I)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;J)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;Landroid/os/Bundle;)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;Landroid/os/IBinder;)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;Ljava/io/Serializable;)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;Ljava/lang/CharSequence;)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;S)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;Z)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;[B)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;[C)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;[D)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;[F)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;[I)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;[J)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;[Landroid/os/Parcelable;)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;[Ljava/lang/CharSequence;)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;[Ljava/lang/String;)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;[S)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtra:(Ljava/lang/String;[Z)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putExtras:(Landroid/content/Intent;)Landroid/content/Intent;" =>  //public
    //    intentPutExtra(s, args, retVars(0), currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
      case "Landroid/content/Intent;.putExtras:(Landroid/os/Bundle;)Landroid/content/Intent;" =>  //public
    //    intentPutExtra(s, args, retVars(0), currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
      case "Landroid/content/Intent;.putIntegerArrayListExtra:(Ljava/lang/String;Ljava/util/ArrayList;)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putParcelableArrayListExtra:(Ljava/lang/String;Ljava/util/ArrayList;)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.putStringArrayListExtra:(Ljava/lang/String;Ljava/util/ArrayList;)Landroid/content/Intent;" =>  //public
        intentPutExtra(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.readFromParcel:(Landroid/os/Parcel;)V" =>  //public
      case "Landroid/content/Intent;.removeCategory:(Ljava/lang/String;)V" =>  //public
      case "Landroid/content/Intent;.removeExtra:(Ljava/lang/String;)V" =>  //public
      case "Landroid/content/Intent;.replaceExtras:(Landroid/content/Intent;)Landroid/content/Intent;" =>  //public
      case "Landroid/content/Intent;.replaceExtras:(Landroid/os/Bundle;)Landroid/content/Intent;" =>  //public
      case "Landroid/content/Intent;.resolveActivity:(Landroid/content/pm/PackageManager;)Landroid/content/ComponentName;" =>  //public
      case "Landroid/content/Intent;.resolveActivityInfo:(Landroid/content/pm/PackageManager;I)Landroid/content/pm/ActivityInfo;" =>  //public
      case "Landroid/content/Intent;.resolveType:(Landroid/content/ContentResolver;)Ljava/lang/String;" =>  //public
      case "Landroid/content/Intent;.resolveType:(Landroid/content/Context;)Ljava/lang/String;" =>  //public
      case "Landroid/content/Intent;.resolveTypeIfNeeded:(Landroid/content/ContentResolver;)Ljava/lang/String;" =>  //public
      case "Landroid/content/Intent;.setAction:(Ljava/lang/String;)Landroid/content/Intent;" =>  //public
        intentSetAction(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.setAllowFds:(Z)V" =>  //public
      case "Landroid/content/Intent;.setClass:(Landroid/content/Context;Ljava/lang/Class;)Landroid/content/Intent;" =>  //public
        intentSetClass(p.getDeclaringClass.global, s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.setClassName:(Landroid/content/Context;Ljava/lang/String;)Landroid/content/Intent;" =>  //public
        intentSetClassName(p.getDeclaringClass.global, s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.setClassName:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;" =>  //public
        intentSetClassName(p.getDeclaringClass.global, s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.setClipData:(Landroid/content/ClipData;)V" =>  //public
      case "Landroid/content/Intent;.setComponent:(Landroid/content/ComponentName;)Landroid/content/Intent;" =>  //public
        intentSetComponent(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.setData:(Landroid/net/Uri;)Landroid/content/Intent;" =>  //public
        intentSetData(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.setDataAndNormalize:(Landroid/net/Uri;)Landroid/content/Intent;" =>  //public
        intentSetData(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.setDataAndType:(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/Intent;" =>  //public
        intentSetDataAndType(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.setDataAndTypeAndNormalize:(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/Intent;" =>  //public
        intentSetDataAndType(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.setExtrasClassLoader:(Ljava/lang/ClassLoader;)V" =>  //public
      case "Landroid/content/Intent;.setFlags:(I)Landroid/content/Intent;" =>  //public
        intentSetFlags(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.setPackage:(Ljava/lang/String;)Landroid/content/Intent;" =>  //public
      case "Landroid/content/Intent;.setSelector:(Landroid/content/Intent;)V" =>  //public
      case "Landroid/content/Intent;.setSourceBounds:(Landroid/graphics/Rect;)V" =>  //public
      case "Landroid/content/Intent;.setType:(Ljava/lang/String;)Landroid/content/Intent;" =>  //public
        intentSetType(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.setTypeAndNormalize:(Ljava/lang/String;)Landroid/content/Intent;" =>  //public
        intentSetType(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/content/Intent;.toInsecureString:()Ljava/lang/String;" =>  //public
      case "Landroid/content/Intent;.toInsecureStringWithClip:()Ljava/lang/String;" =>  //public
      case "Landroid/content/Intent;.toShortString:(Ljava/lang/StringBuilder;ZZZZ)V" =>  //public
      case "Landroid/content/Intent;.toShortString:(ZZZZ)Ljava/lang/String;" =>  //public
      case "Landroid/content/Intent;.toString:()Ljava/lang/String;" =>  //public
      case "Landroid/content/Intent;.toURI:()Ljava/lang/String;" =>  //public
      case "Landroid/content/Intent;.toUri:(I)Ljava/lang/String;" =>  //public
      case "Landroid/content/Intent;.toUriInner:(Ljava/lang/StringBuilder;Ljava/lang/String;I)V" =>  //private
      case "Landroid/content/Intent;.writeToParcel:(Landroid/os/Parcel;I)V" =>  //public
    }
    (newFacts, delFacts, byPassFlag)
  }
  
  /**
   * Landroid/content/Intent;.<init>:(Ljava/lang/String;)V
   */
  private def intentInitWithIntent(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >1)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val paramSlot = VarSlot(args(1), isBase = false, isArg = true)
    val paramValue = s.pointsToSet(paramSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach{ tv =>
      paramValue foreach { pv =>
        val mActionSlot = FieldSlot(pv, AndroidConstants.INTENT_ACTION)
        val mActionValue = s.pointsToSet(mActionSlot, currentContext)
        mActionValue.foreach { mav =>
          newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_ACTION), mav)
        }
        val mCategoriesSlot = FieldSlot(pv, AndroidConstants.INTENT_CATEGORIES)
        val mCategoriesValue = s.pointsToSet(mCategoriesSlot, currentContext)
        mCategoriesValue.foreach{ mcv =>
          newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_CATEGORIES), mcv)
        }
        val mComponentSlot = FieldSlot(pv, AndroidConstants.INTENT_COMPONENT)
        val mComponentValue = s.pointsToSet(mComponentSlot, currentContext)
        mComponentValue.foreach{ mcv =>
          newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_COMPONENT), mcv)
        }
        val mDataSlot = FieldSlot(pv, AndroidConstants.INTENT_URI_DATA)
        val mDataValue = s.pointsToSet(mDataSlot, currentContext)
        mDataValue.foreach{ mdv =>
          newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_URI_DATA), mdv)
        }
        val mTypeSlot = FieldSlot(pv, AndroidConstants.INTENT_MTYPE)
        val mTypeValue = s.pointsToSet(mTypeSlot, currentContext)
        mTypeValue.foreach{ mtv =>
          newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_MTYPE), mtv)
        }
        val mExtrasSlot = FieldSlot(pv, AndroidConstants.INTENT_EXTRAS)
        val mExtrasValue = s.pointsToSet(mExtrasSlot, currentContext)
        mExtrasValue.foreach{ mev =>
          newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_EXTRAS), mev)
        }
      }
    }
    (newfacts, delfacts)
  }
  
  /**
   * Landroid/content/Intent;.<init>:(Landroid/content/Intent;)V
   */
  private def intentInitWithAction(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >1)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val actionSlot = VarSlot(args(1), isBase = false, isArg = true)
    val actionValue = s.pointsToSet(actionSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach{
      tv =>
        actionValue.foreach {
          case cstr: PTAConcreteStringInstance =>
            newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_ACTION), cstr)
          case pstr: PTAPointStringInstance =>
            newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_ACTION), pstr)
          case acStr =>
            newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_ACTION), acStr)
        }
    }
    (newfacts, delfacts)
  }
  
  /**
   * Landroid/content/Intent;.<init>:(Ljava/lang/String;Landroid/net/Uri;)V
   */
  private def intentInitWithActionAndData(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >2)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val actionSlot = VarSlot(args(1), isBase = false, isArg = true)
    val actionValue = s.pointsToSet(actionSlot, currentContext)
    val dataSlot = VarSlot(args(2), isBase = false, isArg = true)
    val dataValue = s.pointsToSet(dataSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach {
      tv =>
//        val interestSlots: ISet[Slot] =
//          Set(FieldSlot(tv, JavaKnowledge.getFieldNameFromFieldFQN(AndroidConstants.INTENT_ACTION)),
//            FieldSlot(tv, JavaKnowledge.getFieldNameFromFieldFQN(AndroidConstants.INTENT_URI_DATA))
//          )
        actionValue.foreach {
          case cstr@PTAConcreteStringInstance(text, c) =>
            newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_ACTION), cstr)
          case pstr@PTAPointStringInstance(c) =>
            newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_ACTION), pstr)
          case acStr =>
            newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_ACTION), acStr)
        }
        dataValue.foreach{ data =>
          newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_URI_DATA), data)
        }
    }
    (newfacts, delfacts)
  }
  
  /**
   * Landroid/content/Intent;.<init>:(Ljava/lang/String;Landroid/net/Uri;Landroid/content/Context;Ljava/lang/Class;)V
   */
  private def intentInitWithActionDataAndComponent(global: Global, s: PTAResult, args: List[String], currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >4)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val actionSlot = VarSlot(args(1), isBase = false, isArg = true)
    val actionValue = s.pointsToSet(actionSlot, currentContext)
    val dataSlot = VarSlot(args(2), isBase = false, isArg = true)
    val dataValue = s.pointsToSet(dataSlot, currentContext)
    val classSlot = VarSlot(args(4), isBase = false, isArg = true)
    val classValue = s.pointsToSet(classSlot, currentContext)
  
    val clazzNames = 
      classValue.map {
        case instance: ClassInstance =>
          PTAConcreteStringInstance(instance.getName, currentContext)
        case value => if (value.isUnknown || value.isNull) {
          value
        } else throw new RuntimeException("Unexpected instance type: " + value)
      }

    val componentNameIns = PTAInstance(new JawaType(AndroidConstants.COMPONENTNAME), currentContext, isNull_ = false)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach{
      tv =>
//        val interestSlots: ISet[Slot] =
//          Set(FieldSlot(tv, JavaKnowledge.getFieldNameFromFieldFQN(AndroidConstants.INTENT_ACTION)),
//            FieldSlot(tv, JavaKnowledge.getFieldNameFromFieldFQN(AndroidConstants.INTENT_URI_DATA)),
//            FieldSlot(tv, JavaKnowledge.getFieldNameFromFieldFQN(AndroidConstants.INTENT_COMPONENT))
//          )
        actionValue.foreach {
          case cstr@PTAConcreteStringInstance(text, c) =>
            newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_ACTION), cstr)
          case pstr@PTAPointStringInstance(c) =>
            newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_ACTION), pstr)
          case acStr =>
            newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_ACTION), acStr)
        }
        dataValue.foreach{ data =>
          newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_URI_DATA), data)
        }
        newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_COMPONENT), componentNameIns)
        clazzNames.foreach {
          case cstr@PTAConcreteStringInstance(text, c) =>
            val recordTyp = new JawaType(text)
            val recOpt = global.getClazz(recordTyp)
            recOpt match {
              case Some(rec) =>
                val packageName = rec.getPackage match {
                  case Some(pkg) => pkg.toPkgString(".")
                  case None => ""
                }
                val pakStr = PTAConcreteStringInstance(packageName, c)
                newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_PACKAGE), pakStr)
                newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_CLASS), cstr)
              case None =>
                val unknownIns = PTAInstance(recordTyp.toUnknown, c, isNull_ = false)
                newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_PACKAGE), unknownIns)
                newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_CLASS), unknownIns)
            }
          case pstr@PTAPointStringInstance(c) =>
            newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_PACKAGE), pstr)
            newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_CLASS), pstr)
          case a =>
            newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_PACKAGE), a)
            newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_CLASS), a)
        }
    }
    (newfacts, delfacts)
  }

  /**
   * Landroid/content/Intent;.<init>:(Landroid/content/Context;Ljava/lang/Class;)V
   */
  private def intentInitWithCC(global: Global, s: PTAResult, args: List[String], currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >2)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val param2Slot = VarSlot(args(2), isBase = false, isArg = true)
    val param2Value = s.pointsToSet(param2Slot, currentContext)
    val clazzNames = 
      param2Value.map {
        case instance: ClassInstance =>
          PTAConcreteStringInstance(instance.getName, currentContext)
        case value => if (value.isUnknown || value.isNull) {
          value
        } else throw new RuntimeException("Unexpected instance type: " + value)
      }
    val componentNameIns = PTAInstance(new JawaType(AndroidConstants.COMPONENTNAME), currentContext, isNull_ = false)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach{
      tv =>
        val mComponentSlot = FieldSlot(tv, AndroidConstants.INTENT_COMPONENT)
        newfacts += new RFAFact(mComponentSlot, componentNameIns)
    }
    clazzNames.foreach {
      case cstr@PTAConcreteStringInstance(text, c) =>
        val recordTyp = new JawaType(text)
        val recOpt = global.getClazz(recordTyp)
        recOpt match {
          case Some(rec) =>
            val packageName = rec.getPackage match {
              case Some(pkg) => pkg.toPkgString(".")
              case None => ""
            }
            val pakStr = PTAConcreteStringInstance(packageName, c)
            newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_PACKAGE), pakStr)
            newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_CLASS), cstr)
          case None =>
            val unknownIns = PTAInstance(recordTyp.toUnknown, c, isNull_ = false)
            newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_PACKAGE), unknownIns)
            newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_CLASS), unknownIns)
        }
      case pstr@PTAPointStringInstance(c) =>
        newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_PACKAGE), pstr)
        newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_CLASS), pstr)
      case a =>
        newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_PACKAGE), a)
        newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_CLASS), a)
    }
    (newfacts, delfacts)
  }

  /**
   * Landroid/content/Intent;.addCategory:(Ljava/lang/String;)Landroid/content/Intent;
   */
  private def intentAddCategory(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >1)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val categorySlot = VarSlot(args(1), isBase = false, isArg = true)
    val categoryValue = s.pointsToSet(categorySlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    var delfacts = isetEmpty[RFAFact]
    thisValue.foreach {
      tv =>
        val mCategorySlot = FieldSlot(tv, AndroidConstants.INTENT_CATEGORIES)
        var mCategoryValue = s.pointsToSet(mCategorySlot, currentContext)
        if(mCategoryValue.isEmpty) {
          val hashsetIns = PTAInstance(new JawaType(Constants.HASHSET), currentContext, isNull_ = false)
          mCategoryValue += hashsetIns
          newfacts += new RFAFact(mCategorySlot, hashsetIns)
        }
        mCategoryValue.foreach{ cv =>
          var hashsetIns = cv
          if(cv.isNull){
            hashsetIns = PTAInstance(new JawaType(Constants.HASHSET), currentContext, isNull_ = false)
            newfacts += new RFAFact(mCategorySlot, hashsetIns)
            delfacts += new RFAFact(mCategorySlot, cv)
          }
          categoryValue.foreach {
            case cstr: PTAConcreteStringInstance =>
              newfacts += new RFAFact(FieldSlot(hashsetIns, Constants.HASHSET_ITEMS), cstr)
            case pstr: PTAPointStringInstance =>
              newfacts += new RFAFact(FieldSlot(hashsetIns,  Constants.HASHSET_ITEMS), pstr)
            case cn =>
              newfacts += new RFAFact(FieldSlot(hashsetIns,  Constants.HASHSET_ITEMS), cn)
          }
        }
        newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), tv)
    }
    (newfacts, delfacts)
  }

  /**
   * Landroid/content/Intent;.clone:()Ljava/lang/Object;
   */
  private def intentClone(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach{
      tv =>
        newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), tv.clone(currentContext))
    }
    (newfacts, delfacts)
  }
  
  
  /**
   * Landroid/content/Intent;.setAction:(Ljava/lang/String;)Landroid/content/Intent;
   */
  private def intentSetAction(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >1)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val actionSlot = VarSlot(args(1), isBase = false, isArg = true)
    val actionValue = s.pointsToSet(actionSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach{
      tv =>
        actionValue.foreach{
          str =>
            thisValue.foreach{
              tv =>
                str match{
                  case cstr: PTAConcreteStringInstance =>
                    newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_ACTION), cstr)
                  case pstr: PTAPointStringInstance =>
                    newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_ACTION), pstr)
                  case _ =>
                    newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_ACTION), str)
                }
            }
        }
        newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), tv)
    }
    (newfacts, delfacts)
  }
  
  
  /**
   * Landroid/content/Intent;.setClass:(Landroid/content/Context;Ljava/lang/Class;)Landroid/content/Intent;
   */
  private def intentSetClass(global: Global, s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >2)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue =s.pointsToSet(thisSlot, currentContext)
    val param2Slot = VarSlot(args(2), isBase = false, isArg = true)
    val param2Value = s.pointsToSet(param2Slot, currentContext)
    val clazzNames = 
      param2Value.map {
        case instance: ClassInstance =>
          PTAConcreteStringInstance(instance.getName, currentContext)
        case value => if (value.isUnknown) {
          value
        } else throw new RuntimeException("Unexpected instance type: " + value)
      }
    val componentNameIns = PTAInstance(new JawaType(AndroidConstants.COMPONENTNAME), currentContext, isNull_ = false)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach{
      tv =>
        val mComponentSlot = FieldSlot(tv, AndroidConstants.INTENT_COMPONENT)
        newfacts += new RFAFact(mComponentSlot, componentNameIns)
        newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), tv)
    }
    clazzNames.foreach {
      case cstr@PTAConcreteStringInstance(text, c) =>
        val recordTyp = new JawaType(text)
        val recOpt = global.getClazz(recordTyp)
        recOpt match {
          case Some(rec) =>
            val packageName = rec.getPackage match {
              case Some(pkg) => pkg.toPkgString(".")
              case None => ""
            }
            val pakStr = PTAConcreteStringInstance(packageName, c)
            newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_PACKAGE), pakStr)
            newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_CLASS), cstr)
          case None =>
            val unknownIns = PTAInstance(recordTyp.toUnknown, c, isNull_ = false)
            newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_PACKAGE), unknownIns)
            newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_CLASS), unknownIns)
        }
      case pstr: PTAPointStringInstance =>
        newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_PACKAGE), pstr)
        newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_CLASS), pstr)
      case a =>
        newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_PACKAGE), a)
        newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_CLASS), a)
    }
    (newfacts, delfacts)
  }
  
  
  /**
   * Landroid/content/Intent;.setClassName:(Landroid/content/Context;Ljava/lang/String;)Landroid/content/Intent;
   */
  private def intentSetClassName(global: Global, s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >2)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val clazzSlot = VarSlot(args(2), isBase = false, isArg = true)
    val clazzValue = s.pointsToSet(clazzSlot, currentContext)
    val componentNameIns = PTAInstance(new JawaType(AndroidConstants.COMPONENTNAME), currentContext, isNull_ = false)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach{
      tv =>
        val mComponentSlot = FieldSlot(tv, AndroidConstants.INTENT_COMPONENT)
        newfacts += new RFAFact(mComponentSlot, componentNameIns)
        newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), tv)
    }
    clazzValue.foreach {
      case cstr@PTAConcreteStringInstance(text, c) =>
        val recordTyp = new JawaType(text)
        val recOpt = global.getClazz(recordTyp)
        recOpt match {
          case Some(rec) =>
            val packageName = rec.getPackage match {
              case Some(pkg) => pkg.toPkgString(".")
              case None => ""
            }
            val pakStr = PTAConcreteStringInstance(packageName, c)
            newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_PACKAGE), pakStr)
            newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_CLASS), cstr)
          case None =>
            val unknownIns = PTAInstance(recordTyp.toUnknown, c, isNull_ = false)
            newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_PACKAGE), unknownIns)
            newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_CLASS), unknownIns)
        }
      case pstr: PTAPointStringInstance =>
        newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_PACKAGE), pstr)
        newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_CLASS), pstr)
      case a =>
        newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_PACKAGE), a)
        newfacts += new RFAFact(FieldSlot(componentNameIns, AndroidConstants.COMPONENTNAME_CLASS), a)
    }
    (newfacts, delfacts)
  }
  
  
  /**
   * Landroid/content/Intent;.setComponent:(Landroid/content/ComponentName;)Landroid/content/Intent;
   */
  private def intentSetComponent(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >1)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val componentSlot = VarSlot(args(1), isBase = false, isArg = true)
    val componentValue = s.pointsToSet(componentSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach{ tv =>
      componentValue.foreach{
        component =>
          thisValue.foreach{ tv =>
            newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_COMPONENT), component)
          }
      }
      newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), tv)
    }
    (newfacts, delfacts)
  }
  
  /**
   * Landroid/content/Intent;.setData:(Landroid/net/Uri;)Landroid/content/Intent;
   */
  private def intentSetData(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >1)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val dataSlot = VarSlot(args(1), isBase = false, isArg = true)
    val dataValue = s.pointsToSet(dataSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach{
      tv =>
        dataValue.foreach{
          data =>
            thisValue.foreach{
              tv =>
                newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_URI_DATA), data)
            }
        }
        newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), tv)
    }
    (newfacts, delfacts)
  }
  
  /**
   * Landroid/content/Intent;.setDataAndType:(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/Intent;
   */
  private def intentSetDataAndType(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >2)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val dataSlot = VarSlot(args(1), isBase = false, isArg = true)
    val dataValue = s.pointsToSet(dataSlot, currentContext)
    val typeSlot = VarSlot(args(2), isBase = false, isArg = true)
    val typeValue = s.pointsToSet(typeSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach{
      tv =>
        dataValue.foreach{
          data =>
            thisValue.foreach{
              tv =>
                newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_URI_DATA), data)
            }
        }
        typeValue.foreach{
          typ =>
            thisValue.foreach{
              tv =>
                newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_MTYPE), typ)
            }
        }
        newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), tv)
    }
    (newfacts, delfacts)
  }
  
  /**
   * Landroid/content/Intent;.setType:(Ljava/lang/String;)Landroid/content/Intent;
   */
  private def intentSetType(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >1)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val typeSlot = VarSlot(args(1), isBase = false, isArg = true)
    val typeValue = s.pointsToSet(typeSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach{
      tv =>
        typeValue.foreach{
          typ =>
            thisValue.foreach{
              tv =>
                newfacts += new RFAFact(FieldSlot(tv, AndroidConstants.INTENT_MTYPE), typ)
            }
        }
        newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), tv)
    }
    (newfacts, delfacts)
  }
  
  /**
   * Landroid/content/Intent;.setPackage:(Ljava/lang/String;)Landroid/content/Intent;
   */
//  private def intentSetPackage(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
//    require(args.size >1)
//    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
//    val thisValue = s.pointsToSet(thisSlot, currentContext)
//    val packageSlot = VarSlot(args(1), isBase = false, isArg = true)
//    val packageValue = s.pointsToSet(packageSlot, currentContext)
//    var newfacts = isetEmpty[RFAFact]
//    val delfacts = isetEmpty[RFAFact]
//    thisValue.foreach{
//      tv =>
//      packageValue.foreach{
//        str =>
//          thisValue.foreach{
//            tv =>
//              str match{
//                case cstr @ PTAConcreteStringInstance(text, c) =>
//                  newfacts += new RFAFact(FieldSlot(tv, JavaKnowledge.getFieldNameFromFieldFQN(AndroidConstants.INTENT_PACKAGE)), cstr)
//                case pstr @ PTAPointStringInstance(c) =>
//                  newfacts += new RFAFact(FieldSlot(tv, JavaKnowledge.getFieldNameFromFieldFQN(AndroidConstants.INTENT_PACKAGE)), pstr)
//                case _ =>
//                  newfacts += new RFAFact(FieldSlot(tv, JavaKnowledge.getFieldNameFromFieldFQN(AndroidConstants.INTENT_PACKAGE)), str)
//              }
//          }
//      }
//      newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), tv)
//    }
//    (newfacts, delfacts)
//  }
  
  /**
   * Landroid/content/Intent;.setFlags:(I)Landroid/content/Intent;
   */
  private def intentSetFlags(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >1)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach{
      tv =>
        newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), tv)
    }
    (newfacts, delfacts)
  }
  
  /**
   * Landroid/content/Intent;.putExtra:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;
   */
  private def intentPutExtra(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >2)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val keySlot = VarSlot(args(1), isBase = false, isArg = true)
    val keyValue = s.pointsToSet(keySlot, currentContext)
    val valueSlot = VarSlot(args(2), isBase = false, isArg = true)
    val valueValue = s.pointsToSet(valueSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    val bundleIns = PTAInstance(new JawaType(AndroidConstants.BUNDLE), currentContext, isNull_ = false)
    thisValue.foreach{
      tv =>
        val mExtraSlot = FieldSlot(tv, AndroidConstants.INTENT_EXTRAS)
        var mExtraValue = s.pointsToSet(mExtraSlot, currentContext)
        if(mExtraValue.isEmpty){
          mExtraValue += bundleIns
          newfacts += new RFAFact(mExtraSlot, bundleIns)
        }
        mExtraValue.foreach{ mev =>
          var entries = isetEmpty[Instance]
          keyValue.foreach{ str =>
            valueValue.foreach{ vv =>
              thisValue foreach{
                ins => entries += PTATupleInstance(str, vv, ins.defSite)
              }
            }
          }
          newfacts ++= entries.map(e => new RFAFact(FieldSlot(mev, AndroidConstants.BUNDLE_ENTRIES), e))
        }
        newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), tv)
    }
    (newfacts, delfacts)
  }
  
  /**
   * Landroid/content/Intent;.getExtras:()Landroid/os/Bundle;
   */
  private def intentGetExtras(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach{ ins =>
      val mExtraSlot = FieldSlot(ins, AndroidConstants.INTENT_EXTRAS)
      val mExtraValue = s.pointsToSet(mExtraSlot, currentContext)
      if(mExtraValue.nonEmpty){
        newfacts ++= mExtraValue.map{mev => new RFAFact(VarSlot(retVar, isBase = false, isArg = false), mev)}
      } else {
        newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), PTAInstance(JavaKnowledge.getTypeFromJawaName(AndroidConstants.BUNDLE).toUnknown, currentContext.copy, isNull_ = false))
      }
    }
    (newfacts, delfacts)
  }
  
  /**
   * Landroid/content/Intent;.getExtra:(Ljava/lang/String;)Ljava/lang/Object;
   */
  private def intentGetExtra(s: PTAResult, args: List[String], retVar: String, currentContext: Context, desiredReturnTyp: JawaType)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >1)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val keySlot = VarSlot(args(1), isBase = false, isArg = true)
    val keyValue = s.pointsToSet(keySlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    if(thisValue.nonEmpty) {
      val mExtraValue = thisValue.map{ins => s.pointsToSet(FieldSlot(ins, AndroidConstants.INTENT_EXTRAS), currentContext)}.reduce(iunion[Instance])
      val entValue = 
        if(mExtraValue.isEmpty)
          isetEmpty
        else
          mExtraValue.map{ins => s.pointsToSet(FieldSlot(ins, AndroidConstants.BUNDLE_ENTRIES), currentContext)}.reduce(iunion[Instance])
      if(entValue.isEmpty && desiredReturnTyp.isObject) {
        newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), PTAInstance(desiredReturnTyp.toUnknown, currentContext.copy, isNull_ = false))
      } else if(keyValue.nonEmpty && !keyValue.exists(_.isInstanceOf[PTAPointStringInstance])) {
        val keys = keyValue.map{k => k.asInstanceOf[PTAConcreteStringInstance].string}
        entValue.foreach{
          v =>
            require(v.isInstanceOf[PTATupleInstance])
            if(keys.contains(v.asInstanceOf[PTATupleInstance].left.asInstanceOf[PTAConcreteStringInstance].string)){
              newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), v.asInstanceOf[PTATupleInstance].right)
            }
        }
      } else if(entValue.nonEmpty) {
        entValue.foreach {
          v =>
            require(v.isInstanceOf[PTATupleInstance])
            newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), v.asInstanceOf[PTATupleInstance].right)
        }
      } else {
        newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), PTAInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown, currentContext.copy, isNull_ = false))
      }
    }
    (newfacts, delfacts)
  }
  
  /**
   * Landroid/content/Intent;.getExtra:(Ljava/lang/String;)Ljava/lang/Object;
   */
  private def intentGetExtraWithDefault(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >2)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val keySlot = VarSlot(args(1), isBase = false, isArg = true)
    val keyValue = s.pointsToSet(keySlot, currentContext)
    val defaultSlot = VarSlot(args(2), isBase = false, isArg = true)
    val defaultValue = s.pointsToSet(defaultSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    if(thisValue.nonEmpty){
      val mExtraValue = thisValue.map{ins => s.pointsToSet(FieldSlot(ins, AndroidConstants.INTENT_EXTRAS), currentContext)}.reduce(iunion[Instance])
      val entValue = 
        if(mExtraValue.isEmpty)
          isetEmpty
        else
          mExtraValue.map{ins => s.pointsToSet(FieldSlot(ins, AndroidConstants.BUNDLE_ENTRIES), currentContext)}.reduce(iunion[Instance])
      if(keyValue.nonEmpty && keyValue.forall(_.isInstanceOf[PTAConcreteStringInstance])){
        val keys = keyValue.map{k => k.asInstanceOf[PTAConcreteStringInstance].string}
        entValue.foreach{
          v =>
            require(v.isInstanceOf[PTATupleInstance])
            if(keys.contains(v.asInstanceOf[PTATupleInstance].left.asInstanceOf[PTAConcreteStringInstance].string)){
              newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), v.asInstanceOf[PTATupleInstance].right)
            }
        }
      } else if(entValue.nonEmpty) {
        entValue.foreach{
          v =>
            require(v.isInstanceOf[PTATupleInstance])
            newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), v.asInstanceOf[PTATupleInstance].right)
        }
      } else {
        newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), PTAInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown, currentContext.copy, isNull_ = false))
      }
    }
    if(newfacts.isEmpty){
      newfacts ++= defaultValue.map(new RFAFact(VarSlot(retVar, isBase = false, isArg = false), _))
    }
    (newfacts, delfacts)
  }
  
}
