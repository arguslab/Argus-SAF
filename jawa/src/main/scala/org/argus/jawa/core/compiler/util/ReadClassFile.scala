/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.util

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object ReadClassFile {

  class CustomClassLoader extends ClassLoader {
    def loadClass(name: String, bytecodes: Array[Byte]): Class[_ <: Any] = {
      defineClass(name, bytecodes, 0, bytecodes.length)
    }
  }
}
