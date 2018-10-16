/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.elements

import org.argus.jawa.core.java_signatures.JavaPackage
import org.argus.jawa.core.util.IList

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
case class JawaPackage(pkg: JavaPackage) extends JavaKnowledge {
  def this(name: String, parent: Option[JawaPackage]) = this(JavaPackage(name = name, parent = parent.map(_.pkg)))
  val name: String = pkg.name
  val parent: Option[JawaPackage] = pkg.parent.map(JawaPackage)
  def getPkgList: IList[JawaPackage] = {
    var pkgs: IList[JawaPackage] = List(this)
    var parentpkg = parent
    while(parentpkg.isDefined) {
      pkgs = parentpkg.get :: pkgs
      parentpkg = parentpkg.get.parent
    }
    pkgs
  }
  def getPkgNameList: IList[String] = {
    getPkgList.map(_.name)
  }
  def toPkgString(sep: String): String = {
    getPkgNameList.mkString(sep)
  }
}
