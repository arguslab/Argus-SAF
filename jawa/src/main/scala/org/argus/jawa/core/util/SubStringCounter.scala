/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.util

import scala.annotation.tailrec

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object SubStringCounter {
	def countSubstring(str1:String, str2:String):Int={
   @tailrec def count(pos:Int, c:Int):Int={
	      val idx=str1 indexOf(str2, pos)
	      if(idx == -1) c else count(idx+str2.length, c+1)
	   }
	   count(0,0)
	}
}
