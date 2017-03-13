/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.util

import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.parser.ResourceFileParser
import org.argus.jawa.core.Global
import org.argus.jawa.core.util.URLInString
import org.sireum.util._

object AndroidUrlCollector {
  def collectUrls(global: Global, file: FileResourceUri): ISet[String] = {
//    val man = AppInfoCollector.analyzeManifest(global.reporter, outUri + "AndroidManifest.xml")
    val afp = AppInfoCollector.analyzeARSC(global.reporter, file)    
    val strs = msetEmpty[String]
    val rfp = new ResourceFileParser
    rfp.parseResourceFile(file)
    strs ++= rfp.getAllStrings
    strs ++= afp.getGlobalStringPool.values
    val sources = global.getApplicationClassCodes
    val code_urls: Set[String] =
      if(sources.nonEmpty){
        sources.map{
          case (name, source) =>
            URLInString.extract(source.code)
        }.reduce(iunion[String])
      } else isetEmpty[String]
    val res_urls: Set[String] =
      if(strs.nonEmpty){
        strs.map{
          str =>
            URLInString.extract(str)
        }.reduce(iunion[String])
      } else isetEmpty[String]   
    code_urls ++ res_urls
  }
}
