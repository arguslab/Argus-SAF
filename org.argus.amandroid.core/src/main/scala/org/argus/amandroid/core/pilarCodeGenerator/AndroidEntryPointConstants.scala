/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.pilarCodeGenerator

import org.argus.jawa.core.Signature


/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object AndroidEntryPointConstants {
	final val ACTIVITY_CLASS = "android.app.Activity"
	final val SERVICE_CLASS = "android.app.Service"
	final val BROADCAST_RECEIVER_CLASS = "android.content.BroadcastReceiver"
	final val CONTENT_PROVIDER_CLASS = "android.content.ContentProvider"
	final val APPLICATION_CLASS = "[|android:app:Application|]"
	
	final val APPLICATION_ONCREATE = "onCreate:()V"
	final val APPLICATION_ONTERMINATE = "onTerminate()V"
	  
	final val ACTIVITY_ONCREATE = "onCreate:(Landroid/os/Bundle;)V"
	final val ACTIVITY_ONSTART = "onStart:()V"
	final val ACTIVITY_ONRESTOREINSTANCESTATE = "onRestoreInstanceState:(Landroid/os/Bundle;)V"
	final val ACTIVITY_ONPOSTCREATE = "onPostCreate:(Landroid/os/Bundle;)V"
	final val ACTIVITY_ONRESUME = "onResume:()V"
	final val ACTIVITY_ONPOSTRESUME = "onPostResume:()V"
	final val ACTIVITY_ONCREATEDESCRIPTION = "onCreateDescription:()Ljava/lang/CharSequence;"
	final val ACTIVITY_ONSAVEINSTANCESTATE = "onSaveInstanceState:(Landroid/os/Bundle;)V"
	final val ACTIVITY_ONPAUSE = "onPause:()V"
	final val ACTIVITY_ONSTOP = "onStop:()V"
	final val ACTIVITY_ONRESTART = "onRestart:()V"
	final val ACTIVITY_ONDESTROY = "onDestroy:()V"
	
	final val SERVICE_ONCREATE = "onCreate:()V"
	final val SERVICE_ONSTART1 = "onStart:(Landroid/content/Intent;I)V"
	final val SERVICE_ONSTART2 = "onStartCommand:(Landroid/content/Intent;II)I"
	final val SERVICE_ONBIND = "onBind:(Landroid/content/Intent;)Landroid/os/IBinder;"
	final val SERVICE_ONREBIND = "onRebind:(Landroid/content/Intent;)V"
	final val SERVICE_ONUNBIND = "onUnbind:(Landroid/content/Intent;)Z"
	final val SERVICE_ONDESTROY = "onDestroy:()V"
	
	final val BROADCAST_ONRECEIVE = "onReceive:(Landroid/content/Context;Landroid/content/Intent;)V"
	
	final val CONTENTPROVIDER_ONCREATE = "onCreate:()Z"
	
	final val INTENT_NAME = "android.content.Intent"
	final val ACTIVITY_SETINTENT_SIG = new Signature("Landroid/app/Activity;.setIntent:(Landroid/content/Intent;)V")
	
	private final val applicationMethods = List(APPLICATION_ONCREATE, APPLICATION_ONTERMINATE)
	private final val activityMethods = List(ACTIVITY_ONCREATE, ACTIVITY_ONDESTROY, ACTIVITY_ONPAUSE,
		ACTIVITY_ONRESTART, ACTIVITY_ONRESUME, ACTIVITY_ONSTART, ACTIVITY_ONSTOP,
		ACTIVITY_ONSAVEINSTANCESTATE, ACTIVITY_ONRESTOREINSTANCESTATE,
		ACTIVITY_ONCREATEDESCRIPTION, ACTIVITY_ONPOSTCREATE, ACTIVITY_ONPOSTRESUME)
	private final val serviceMethods = List(SERVICE_ONCREATE, SERVICE_ONDESTROY, SERVICE_ONSTART1,
		SERVICE_ONSTART2, SERVICE_ONBIND, SERVICE_ONREBIND, SERVICE_ONUNBIND)
	private final val broadcastMethods = List(BROADCAST_ONRECEIVE)
	private final val contentproviderMethods = List(CONTENTPROVIDER_ONCREATE)
	
	def getApplicationLifecycleMethods: List[String] = applicationMethods
	
	def getActivityLifecycleMethods: List[String] = activityMethods
	
	def getServiceLifecycleMethods: List[String] = serviceMethods
	
	def getBroadcastLifecycleMethods: List[String] = broadcastMethods
	
	def getContentproviderLifecycleMethods: List[String] = contentproviderMethods
}
