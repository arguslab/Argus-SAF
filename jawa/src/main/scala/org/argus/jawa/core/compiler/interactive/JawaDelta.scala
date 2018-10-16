/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.interactive

import org.argus.jawa.core.ast.CompilationUnit
import org.argus.jawa.core.io.AbstractFile
import org.argus.jawa.core.util._

case class JawaDelta(changedOrDeletedCUFiles: ISet[AbstractFile], changedOrAddedCUs: ISeq[CompilationUnit])
