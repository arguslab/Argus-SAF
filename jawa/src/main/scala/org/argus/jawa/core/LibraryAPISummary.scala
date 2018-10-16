/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core

import java.io.{BufferedReader, FileReader, StringReader}

import org.argus.jawa.core.elements.JawaType
import org.argus.jawa.core.util._

trait LibraryAPISummary {
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
            libraryPackagePrefixes += str.substring(0, str.length - 2)
          else libraryPackages += str
        case None =>
      }
      line = Option(rdr.readLine())
    }
    rdr.close()
  }

  def isLibraryClass: JawaType => Boolean = { typ =>
    libraryPackages.contains(typ.getPackageName) ||
    libraryPackagePrefixes.exists(typ.getPackageName.startsWith)
  }
}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
class NoneLibraryAPISummary extends LibraryAPISummary {
  private val appPackages: MSet[String] = msetEmpty
  private val appPackagePrefixes: MSet[String] = msetEmpty
  private def doLoad(rdr: BufferedReader): Unit = {
    var line = Option(rdr.readLine())
    while(line.isDefined){
      line match {
        case Some(str) =>
          if(str.endsWith(".*"))
            appPackagePrefixes += str.substring(0, str.length - 2)
          else appPackages += str
        case None =>
      }
      line = Option(rdr.readLine())
    }
  }
  def load(filePath: String): Unit = {
    val rdr: BufferedReader = new BufferedReader(new FileReader(filePath))
    doLoad(rdr)
    rdr.close()
  }
  def loadFromString(str: String): Unit = {
    val rdr: BufferedReader = new BufferedReader(new StringReader(str))
    doLoad(rdr)
    rdr.close()
  }
  override def isLibraryClass: JawaType => Boolean = { typ =>
    !appPackages.contains(typ.getPackageName) && !appPackagePrefixes.exists(typ.getPackageName.startsWith)
  }
}

object NoLibraryAPISummary extends LibraryAPISummary {
  override def isLibraryClass: JawaType => Boolean = _ => false
}