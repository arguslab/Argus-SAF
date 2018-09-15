/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.dedex.`type`

import org.argus.jawa.ast.CompilationUnit
import org.argus.jawa.core.io.AbstractFile

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
trait CompilerAccess {

  val global: org.argus.jawa.compiler.interactive.Global

  def compilationUnitOfFile(f: AbstractFile): Option[CompilationUnit]
}
