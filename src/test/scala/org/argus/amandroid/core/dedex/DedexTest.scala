/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.dedex

import org.argus.amandroid.core.decompile.{DecompileLayout, DecompilerSettings}
import org.argus.jawa.core.{JawaType, NoReporter, ResolveLevel}
import org.argus.jawa.core.sourcefile.SourcefileParser
import org.scalatest.{FlatSpec, Matchers}
import org.sireum.util.FileUtil

/**
  * Created by fgwei on 4/8/17.
  */
class DedexTest extends FlatSpec with Matchers {

  val recordFilter: (JawaType => Boolean) = { ot =>
    if(ot.name.startsWith("android.support.v4")){
      false
    } else if (ot.name.startsWith("android.support.v13")) {
      false
    } else if (ot.name.startsWith("android.support.v7")){
      false
    } else if (ot.name.startsWith("android.support.design")) {
      false
    } else if (ot.name.startsWith("android.support.annotation")) {
      false
    } else if(ot.name.endsWith(".BuildConfig") ||
      ot.name.endsWith(".Manifest") ||
      ot.name.contains(".Manifest$") ||
      ot.name.endsWith(".R") ||
      ot.name.contains(".R$")) {
      false
    } else true
  }

  "Dedex data.dex" should "produce expected code" in {
    val dedex = new JawaDeDex
    val dexUri = FileUtil.toUri(getClass.getResource("/dexes/data.dex").getPath)
    dedex.decompile(dexUri, None, recordFilter, DecompilerSettings(debugMode = false, removeSupportGen = true, forceDelete = false, DecompileLayout("")))
    dedex.getCodes map { case (_, code) =>
      noException should be thrownBy SourcefileParser.parse(code, ResolveLevel.BODY, new NoReporter)
    }
    assert(!dedex.getCodes.exists{case (_, code) => code.contains("@INVALID_")})
  }

  "Dedex comprehensive.dex" should "produce expected code" in {
    val dedex = new JawaDeDex
    val dexUri = FileUtil.toUri(getClass.getResource("/dexes/comprehensive.dex").getPath)
    dedex.decompile(dexUri, None, recordFilter, DecompilerSettings(debugMode = false, removeSupportGen = true, forceDelete = false, DecompileLayout("")))
    dedex.getCodes map { case (_, code) =>
      noException should be thrownBy SourcefileParser.parse(code, ResolveLevel.BODY, new NoReporter)
    }
    assert(!dedex.getCodes.exists{case (_, code) => code.contains("@INVALID_")})
  }

  "Dedex comprehensive.odex" should "produce expected code" in {
    val dedex = new JawaDeDex
    val dexUri = FileUtil.toUri(getClass.getResource("/dexes/comprehensive.odex").getPath)
    dedex.decompile(dexUri, None, recordFilter, DecompilerSettings(debugMode = false, removeSupportGen = true, forceDelete = false, DecompileLayout("")))
    dedex.getCodes map { case (_, code) =>
      noException should be thrownBy SourcefileParser.parse(code, ResolveLevel.BODY, new NoReporter)
    }
    assert(!dedex.getCodes.exists{case (_, code) => code.contains("@INVALID_")})
  }

  "Dedex oat file BasicDreams.odex" should "produce expected code" in {
    val dedex = new JawaDeDex
    val dexUri = FileUtil.toUri(getClass.getResource("/dexes/BasicDreams.odex").getPath)
    dedex.decompile(dexUri, None, recordFilter, DecompilerSettings(debugMode = true, removeSupportGen = true, forceDelete = false, DecompileLayout(""), api = 25))
    dedex.getCodes map { case (_, code) =>
      noException should be thrownBy SourcefileParser.parse(code, ResolveLevel.BODY, new NoReporter)
    }
    assert(!dedex.getCodes.exists{case (_, code) => code.contains("@INVALID_")})
  }
}
