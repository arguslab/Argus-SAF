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

import scala.language.implicitConversions

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
package object io {
  type JManifest = java.util.jar.Manifest
  type JFile = java.io.File

  implicit def enrichManifest(m: JManifest): Jar.WManifest = Jar.WManifest(m)
}
