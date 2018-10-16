/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.security

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object AndroidProblemCategories {
  
  /**
   * following are vulnerability categories
   */
	final val VUL_INFORMATION_LEAK = "vulnerability:information_leak"
	final val VUL_CAPABILITY_LEAK = "vulnerability:capability_leak"
	final val VUL_CONFUSED_DEPUTY = "vulnerability:confused_deputy"
	  
	/**
	 * following are maliciousness categories
	 */
	final val MAL_INFORMATION_LEAK = "maliciousness:information_theft"
}
