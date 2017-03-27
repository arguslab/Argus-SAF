/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin.apiMisuse

import org.argus.amandroid.plugin.{ApiMisuseChecker, ApiMisuseResult}
import org.argus.jawa.alir.dataFlowAnalysis.InterproceduralDataFlowGraph
import org.argus.jawa.core.Global
import org.sireum.util._

/*
 * @author <a href="mailto:i@flanker017.me">Qidan He</a>
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class SSLTLSMisuse extends ApiMisuseChecker {
  val name = "SSLTLSMisuse"
//  private final val API_SIG = "setHostnameVerifier:(Lorg/apache/http/conn/ssl/X509HostnameVerifier;)V"
  private final val VUL_PARAM = "@@org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER"

  private final val badTrustManagerNames: ISet[String] = Set(
    "AcceptAllTrustManager",
    "AllTrustManager",
    "DummyTrustManager",
    "EasyX509TrustManager",
    "FakeTrustManager",
    "FakeX509TrustManager",
    "FullX509TrustManager",
    "NaiveTrustManager",
    "NonValidatingTrustManager",
    "NullTrustManager",
    "OpenTrustManager",
    "PermissiveX509TrustManager",
    "SimpleTrustManager",
    "SimpleX509TrustManager",
    "TrivialTrustManager",
    "TrustAllManageranager",
    "TrustAllTrustManager",
    "TrustAnyCertTrustManager",
    "UnsafeX509TrustManager")

  private final val badSSLSocketFactoryNames: ISet[String] = Set(
    "AcceptAllSSLSocketFactory",
    "AllTrustingSSLSocketFactory",
    "AllTrustSSLSocketFactory",
    "AllSSLSocketFactory",
    "DummySSLSocketFactory",
    "EasySSLSocketFactory",
    "FakeSSLSocketFactory",
    "InsecureSSLSocketFactory",
    "NonValidatingSSLSocketFactory",
    "NaiveSslSocketFactory",
    "SimpleSSLSocketFactory",
    "SSLSocketFactoryUntrustedCert",
    "SSLUntrustedSocketFactory",
    "TrustAllSSLSocketFactory",
    "TrustEveryoneSocketFactory",
    "NaiveTrustManagerFactory",
    "LazySSLSocketFactory",
    "UnsecureTrustManagerFactory"
  )
    
  def check(global: Global, idfg: Option[InterproceduralDataFlowGraph]): ApiMisuseResult = {
    val result: MMap[(String, String), String] = mmapEmpty
    global.getApplicationClassCodes foreach { case (typ, file) =>
      if(badTrustManagerNames.contains(typ.simpleName)) {
        result((typ.name, "")) = "Use bad TrustManager!"
      }
      if(badSSLSocketFactoryNames.contains(typ.simpleName)) {
        result((typ.name, "")) = "Use bad SSLSocketFactory!"
      }
      if(file.code.contains(VUL_PARAM)) {
        result((typ.name, "")) = "Using wrong SSL hostname configuration!"
      }
    }
    ApiMisuseResult(name, result.toMap)
  }

}
