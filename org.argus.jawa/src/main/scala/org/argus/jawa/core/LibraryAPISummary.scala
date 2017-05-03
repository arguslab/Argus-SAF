/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core

import java.io.{BufferedReader, FileReader}

import org.argus.jawa.core.util._

trait LibraryAPISummary {
  /**
    * check given API name is present in library
    */
  def isLibraryAPI(apiName: String): Boolean

  def isLibraryClass: JawaType => Boolean
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class DefaultLibraryAPISummary(filePath: String) extends LibraryAPISummary {

  private val libraryPackages: MSet[String] = msetEmpty
  private val libraryPackagePrefixes: MSet[String] = msetEmpty

  load()

  def load(): Unit = {
    val rdr: BufferedReader = new BufferedReader(new FileReader(filePath))
    var line = Option(rdr.readLine())
    while(line.isDefined){
      line match {
        case Some(str) =>
          if(str.endsWith(".*"))
            libraryPackagePrefixes += str.substring(0, str.length - 1)
          else libraryPackages += str
        case None =>
      }
      line = Option(rdr.readLine())
    }
    rdr.close()
  }

  /**
    * check given API name is present in library
    */
  def isLibraryAPI(apiName: String): Boolean = {
    libraryPackages.contains(apiName) ||
    libraryPackagePrefixes.exists(apiName.startsWith)
  }

  def isLibraryClass: JawaType => Boolean = { typ =>
    libraryPackages.contains(typ.getPackageName) ||
    libraryPackagePrefixes.exists(typ.getPackageName.startsWith)
  }
}

object NoLibraryAPISummary extends LibraryAPISummary {
  /**
    * check given API name is present in library
    */
  override def isLibraryAPI(apiName: String): Boolean = false

  override def isLibraryClass: JawaType => Boolean = _ => false
}