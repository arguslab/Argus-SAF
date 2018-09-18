/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.interactive

import org.argus.jawa.core.ast.CompilationUnit
import org.argus.jawa.core.io.AbstractFile
import org.argus.jawa.core.util._

case class JawaDelta(changedOrDeletedCUFiles: ISet[AbstractFile], changedOrAddedCUs: ISeq[CompilationUnit])
