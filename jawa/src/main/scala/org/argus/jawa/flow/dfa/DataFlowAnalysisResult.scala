/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.dfa

import org.argus.jawa.flow.AlirNode
import org.argus.jawa.core.util.ISet

/**
 * Provide an Interface to let the developer get data facts corresponding
 * to each statement.
 * 
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
trait DataFlowAnalysisResult[N <: AlirNode, LatticeElement] {
  def entrySet: N => ISet[LatticeElement]
}
