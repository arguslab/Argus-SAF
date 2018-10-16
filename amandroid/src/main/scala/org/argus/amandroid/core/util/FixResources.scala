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

import org.argus.jawa.core.util._
import java.io.PrintWriter

import org.argus.amandroid.core.dedex.JawaDeDex
import org.argus.amandroid.core.parser.ManifestParser
import org.argus.jawa.core.util.FileUtil

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object FixResources {
  def fix(decFolder: FileResourceUri, dedex: JawaDeDex): Unit = {
    val xml = FileUtil.appendFileName(decFolder, "AndroidManifest.xml")
    if(dedex.haveRenamedElements) {
      var filestr = FileUtil.readFileContent(xml)
      val (pkg, recs) = ManifestParser.loadPackageAndComponentNames(xml)
      val newpkg = dedex.mapPackage(pkg)
      filestr = filestr.replaceAll("\"" + pkg + "\"", "\"" + newpkg + "\"")
      recs.foreach {
        case (origstr, comclass) =>
          val newclass = dedex.mapRecord(comclass)
          filestr = filestr.replaceAll("\"" + origstr + "\"", "\"" + newclass + "\"")
      }
      val pw = new PrintWriter(FileUtil.toFile(xml))
      pw.write(filestr)
      pw.flush()
      pw.close()
    }
  }
}
