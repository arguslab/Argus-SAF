/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta.flowFunction

import org.argus.jawa.alir.controlFlowGraph.ICFGNode
import org.argus.jawa.alir.dataFlowAnalysis.MonotonicFunction
import org.argus.jawa.alir.pta.{PTAResult, PTASlot, VarSlot}
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, ReachingFactsAnalysisHelper}
import org.argus.jawa.compiler.parser._
import org.argus.jawa.core.ExceptionCenter
import org.argus.jawa.core.util.{IMap, ISet, imapEmpty, isetEmpty}




