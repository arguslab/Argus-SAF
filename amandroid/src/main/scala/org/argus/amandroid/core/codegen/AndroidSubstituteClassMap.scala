/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.codegen

import org.argus.jawa.core.elements.JawaType
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object AndroidSubstituteClassMap {
	def getSubstituteClassMap: IMap[JawaType, JawaType] = {
	  val map: MMap[JawaType, JawaType] = mmapEmpty
	  map.put(new JawaType("android.content.Context"), new JawaType("android.content.ContextWrapper"))
    map.put(new JawaType("android.view.Menu"), new JawaType("com.android.internal.view.menu.MenuBuilder"))
    map.put(new JawaType("android.content.SharedPreferences"), new JawaType("android.app.SharedPreferencesImpl"))
    map.put(new JawaType("android.os.IBinder"), new JawaType("android.os.Binder"))
    map.put(new JawaType("android.hardware.display.IDisplayManager"), new JawaType("android.hardware.display.DisplayManager"))
	  map.toMap
	}
}
