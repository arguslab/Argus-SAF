/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.dataRecorder

import org.argus.jawa.flow.dda.InterProceduralDataDependenceInfo
import org.argus.jawa.flow.dfa.InterProceduralDataFlowGraph


/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
case class AmandroidResult(idfg: InterProceduralDataFlowGraph, ddg: InterProceduralDataDependenceInfo)
