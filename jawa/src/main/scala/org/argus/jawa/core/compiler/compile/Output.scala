/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.compile

import org.argus.jawa.core.util._
import java.io.File

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
trait Output {
  
}

trait SingleOutput extends Output {

  /** The directory where class files should be generated.
    * Incremental compilation will manage the class files in this directory.
    * In particular, outdated class files will be deleted before compilation.
    * It is important that this directory is exclusively used for one set of sources. */
  def outputDirectory(): File
}

trait MultipleOutput extends Output {

  trait OutputGroup {
    /** The directory where source files are stored for this group.
      * Source directories should uniquely identify the group for a source file. */
    def sourceDirectory(): File

    /** The directory where class files should be generated.
      * Incremental compilation will manage the class files in this directory.
      * In particular, outdated class files will be deleted before compilation.
      * It is important that this directory is exclusively used for one set of sources. */
    def outputDirectory(): File
  }

  def outputGroups(): IList[OutputGroup]
}
