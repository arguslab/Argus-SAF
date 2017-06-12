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
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, SimHeap}
import org.argus.jawa.core.{JawaMethod, JawaType}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class UriModel extends ModelCall {
  final val TITLE = "UriModel"
  def isModelCall(p: JawaMethod): Boolean = p.getDeclaringClass.getName.equals("android.net.Uri")
    
  def doModelCall(s: PTAResult, p: JawaMethod, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    var newFacts = isetEmpty[RFAFact]
    var delFacts = isetEmpty[RFAFact]
    var byPassFlag = true
    p.getSignature.signature match{
      case "Landroid/net/Uri;.<clinit>:()V" =>  //static constructor
      case "Landroid/net/Uri;.<init>:()V" =>  //private constructor
      case "Landroid/net/Uri;.<init>:(Landroid/net/Uri$1;)V" =>  //synthetic constructor
      case "Landroid/net/Uri;.access$300:()Ljava/lang/String;" =>  //static synthetic
      case "Landroid/net/Uri;.access$600:()Ljava/lang/String;" =>  //static synthetic
      case "Landroid/net/Uri;.buildUpon:()Landroid/net/Uri$Builder;" =>  //public abstract
      case "Landroid/net/Uri;.compareTo:(Landroid/net/Uri;)I" =>  //public
      case "Landroid/net/Uri;.compareTo:(Ljava/lang/Object;)I" =>  //public synthetic
      case "Landroid/net/Uri;.decode:(Ljava/lang/String;)Ljava/lang/String;" =>  //public static
      case "Landroid/net/Uri;.encode:(Ljava/lang/String;)Ljava/lang/String;" =>  //public static
      case "Landroid/net/Uri;.encode:(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" =>  //public static
      case "Landroid/net/Uri;.equals:(Ljava/lang/Object;)Z" =>  //public
      case "Landroid/net/Uri;.fromFile:(Ljava/io/File;)Landroid/net/Uri;" =>  //public static
      case "Landroid/net/Uri;.fromParts:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri;" =>  //public static
      case "Landroid/net/Uri;.getAuthority:()Ljava/lang/String;" =>  //public abstract
      case "Landroid/net/Uri;.getBooleanQueryParameter:(Ljava/lang/String;Z)Z" =>  //public
      case "Landroid/net/Uri;.getCanonicalUri:()Landroid/net/Uri;" =>  //public
      case "Landroid/net/Uri;.getEncodedAuthority:()Ljava/lang/String;" =>  //public abstract
      case "Landroid/net/Uri;.getEncodedFragment:()Ljava/lang/String;" =>  //public abstract
      case "Landroid/net/Uri;.getEncodedPath:()Ljava/lang/String;" =>  //public abstract
      case "Landroid/net/Uri;.getEncodedQuery:()Ljava/lang/String;" =>  //public abstract
      case "Landroid/net/Uri;.getEncodedSchemeSpecificPart:()Ljava/lang/String;" =>  //public abstract
      case "Landroid/net/Uri;.getEncodedUserInfo:()Ljava/lang/String;" =>  //public abstract
      case "Landroid/net/Uri;.getFragment:()Ljava/lang/String;" =>  //public abstract
      case "Landroid/net/Uri;.getHost:()Ljava/lang/String;" =>  //public abstract
      case "Landroid/net/Uri;.getLastPathSegment:()Ljava/lang/String;" =>  //public abstract
      case "Landroid/net/Uri;.getPath:()Ljava/lang/String;" =>  //public abstract
      case "Landroid/net/Uri;.getPathSegments:()Ljava/util/List;" =>  //public abstract
      case "Landroid/net/Uri;.getPort:()I" =>  //public abstract
      case "Landroid/net/Uri;.getQuery:()Ljava/lang/String;" =>  //public abstract
      case "Landroid/net/Uri;.getQueryParameter:(Ljava/lang/String;)Ljava/lang/String;" =>  //public
      case "Landroid/net/Uri;.getQueryParameterNames:()Ljava/util/Set;" =>  //public
      case "Landroid/net/Uri;.getQueryParameters:(Ljava/lang/String;)Ljava/util/List;" =>  //public
      case "Landroid/net/Uri;.getScheme:()Ljava/lang/String;" =>  //public abstract
      case "Landroid/net/Uri;.getSchemeSpecificPart:()Ljava/lang/String;" =>  //public abstract
      case "Landroid/net/Uri;.getUserInfo:()Ljava/lang/String;" =>  //public abstract
      case "Landroid/net/Uri;.hashCode:()I" =>  //public
      case "Landroid/net/Uri;.isAbsolute:()Z" =>  //public
      case "Landroid/net/Uri;.isAllowed:(CLjava/lang/String;)Z" =>  //private static
      case "Landroid/net/Uri;.isHierarchical:()Z" =>  //public abstract
      case "Landroid/net/Uri;.isOpaque:()Z" =>  //public
      case "Landroid/net/Uri;.isRelative:()Z" =>  //public abstract
      case "Landroid/net/Uri;.normalizeScheme:()Landroid/net/Uri;" =>  //public
      case "Landroid/net/Uri;.parse:(Ljava/lang/String;)Landroid/net/Uri;" =>  //public static
        uriParse(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/net/Uri;.toSafeString:()Ljava/lang/String;" =>  //public
      case "Landroid/net/Uri;.toString:()Ljava/lang/String;" =>  //public abstract
      case "Landroid/net/Uri;.withAppendedPath:(Landroid/net/Uri;Ljava/lang/String;)Landroid/net/Uri;" =>  //public static
      case "Landroid/net/Uri;.writeToParcel:(Landroid/os/Parcel;Landroid/net/Uri;)V" =>  //public static
    }
    (newFacts, delFacts, byPassFlag)
  }
  
  /**
   * Landroid/net/Uri;.parse:(Ljava/lang/String;)Landroid/net/Uri;
   */
  private def uriParse(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.nonEmpty)
    val strSlot = VarSlot(args.head, isBase = false, isArg = true)
    val strValue = s.pointsToSet(strSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    val stringUriIns = PTAInstance(new JawaType(AndroidConstants.URI_STRING_URI), currentContext)
    newfacts += new RFAFact(VarSlot(retVar, isBase = false, isArg = false), stringUriIns)
    strValue.foreach {
      case cstr: PTAConcreteStringInstance =>
        newfacts += new RFAFact(FieldSlot(stringUriIns, AndroidConstants.URI_STRING_URI_URI_STRING), cstr)
      case pstr: PTAPointStringInstance =>
        newfacts += new RFAFact(FieldSlot(stringUriIns, AndroidConstants.URI_STRING_URI_URI_STRING), pstr)
      case sv =>
        newfacts += new RFAFact(FieldSlot(stringUriIns, AndroidConstants.URI_STRING_URI_URI_STRING), sv)
    }
    (newfacts, delfacts)
  }
}
