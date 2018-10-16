/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.util

import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.jawa.core.Global
import org.argus.jawa.core.util.URLInString
import org.argus.jawa.core.util._

object AndroidUrlCollector {
  def collectUrls(global: Global, file: FileResourceUri): ISet[String] = {
    val afp = AppInfoCollector.analyzeARSC(global.reporter, file)    
    val strs = msetEmpty[String]
//    val rfp = new ResourceFileParser
//    rfp.parseResourceFile(file)
//    strs ++= rfp.getAllStrings
    strs ++= afp.getGlobalStringPool.values
    val sources = global.getApplicationClassCodes
    val code_urls: Set[String] =
      if(sources.nonEmpty){
        sources.map{
          case (_, source) =>
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
