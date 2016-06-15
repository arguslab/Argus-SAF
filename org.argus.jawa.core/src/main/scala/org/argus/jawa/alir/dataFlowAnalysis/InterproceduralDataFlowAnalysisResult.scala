/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.dataFlowAnalysis

import org.argus.jawa.alir.controlFlowGraph.ICFGNode
import org.sireum.util.ISet

/**
 * Provide an Interface to let the developer get data facts corresponding
 * to each statement.
 * 
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
trait InterproceduralDataFlowAnalysisResult[LatticeElement] {
  def entrySet: ICFGNode => ISet[LatticeElement]
}
