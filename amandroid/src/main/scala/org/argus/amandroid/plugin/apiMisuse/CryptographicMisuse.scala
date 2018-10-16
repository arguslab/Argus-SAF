/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin.apiMisuse

import org.argus.amandroid.plugin.{ApiMisuseChecker, ApiMisuseResult}
import org.argus.jawa.flow.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.flow.util.ExplicitValueFinder
import org.argus.jawa.core.ast.CallStatement
import org.argus.jawa.core.{Global, JawaMethod}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class CryptographicMisuse extends ApiMisuseChecker {

  val name = "CryptographicMisuse"

  def check(global: Global, idfgOpt: Option[InterProceduralDataFlowGraph]): ApiMisuseResult = {
    val misusedApis: MMap[(String, String), String] = mmapEmpty
    global.getApplicationClassCodes foreach { case (typ, f) =>
      if(f.code.contains("Ljavax/crypto/Cipher;.getInstance:(Ljava/lang/String;")) {
        global.getClazz(typ) match {
          case Some(c) =>
            c.getDeclaredMethods.foreach { m =>
              val rule1Res = ECBCheck(m)
              rule1Res foreach { uri =>
                misusedApis((m.getSignature.signature, uri)) = "Use ECB mode!"
              }
            }
          case None =>
        }
      }
      if(f.code.contains("Ljavax/crypto/spec/IvParameterSpec;.<init>:([B")) {
        global.getClazz(typ) match {
          case Some(c) =>
            c.getDeclaredMethods.foreach { m =>
              val rule2Res = IVCheck(m)
              rule2Res foreach { uri =>
                misusedApis((m.getSignature.signature, uri)) = "Use non-random IV!"
              }
            }
          case None =>
        }
      }
    }
    ApiMisuseResult(name, misusedApis.toMap)
  }

  /**
   * Rule 1 forbids the use of ECB mode because ECB mode is deterministic and not stateful, 
   * thus cannot be IND-CPA secure.
   */
  private def ECBCheck(method: JawaMethod): ISet[String] = {
    val result: MSet[String] = msetEmpty
    method.getBody.resolvedBody.locations.foreach { l =>
      l.statement match {
        case cs: CallStatement =>
          if(CryptographicConstants.getCipherGetinstanceAPIs.contains(cs.signature.signature)) {
            val value = ExplicitValueFinder.findExplicitLiteralForArgs(method, l, cs.arg(0)).filter(_.isString).map(_.getString)
            value.foreach { str =>
              if(CryptographicConstants.getECBSchemes.contains(str)) result += l.locationUri
            }
          }
        case _ =>
      }
    }
    result.toSet
  }

  /**
    * Rule 2 Do not use a non-random IV for CBC encryption.
    */
  private def IVCheck(method: JawaMethod): ISet[String] = {
    val result: MSet[String] = msetEmpty
    method.getBody.resolvedBody.locations foreach { l =>
      l.statement match {
        case cs: CallStatement =>
          if(CryptographicConstants.getIVParameterInitAPIs.contains(cs.signature.signature)) {
            if(ExplicitValueFinder.isArgStaticBytes(method, l, cs.arg(0))) {
              result += l.locationUri
            }
          }
        case _ =>
      }
    }
    result.toSet
  }
}
