/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.util

import java.io.{File, FileInputStream}

import org.argus.amandroid.core.parser.ManifestParser
import org.scalatest.{FlatSpec, Matchers}

class GuessAppPackagesTest extends FlatSpec with Matchers {
  implicit def manifest(path: String): TestManifest = new TestManifest(getClass.getResource(path).getPath)

  "/manifests/AndroidManifest1.xml" gen_pkg_names (
    "com.gamesdj.desafiando",
    "com.google.android.gms",
    "com.unity3d"
  )

  "/manifests/AndroidManifest2.xml" gen_pkg_names "org.arguslab.icc_implicit_action"

  class TestManifest(path: String) {
    def gen_pkg_names(expected: String*): Unit = {
      path should "generate pkg name as expected" in {
        val manifestIS = new FileInputStream(new File(path))
        val mfp = new ManifestParser
        mfp.loadClassesFromTextManifest(manifestIS)
        manifestIS.close()
        val guessed = GuessAppPackages.guess(mfp)
        assert(guessed.size == expected.size && (guessed -- expected).isEmpty)
      }
    }
  }
}
