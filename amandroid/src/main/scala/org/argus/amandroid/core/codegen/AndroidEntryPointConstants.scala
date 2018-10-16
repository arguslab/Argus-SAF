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

import org.argus.jawa.core.elements.Signature


/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object AndroidEntryPointConstants {
	final lazy val ACTIVITY_CLASS = "android.app.Activity"
	final lazy val SERVICE_CLASS = "android.app.Service"
	final lazy val BROADCAST_RECEIVER_CLASS = "android.content.BroadcastReceiver"
	final lazy val CONTENT_PROVIDER_CLASS = "android.content.ContentProvider"
	final lazy val APPLICATION_CLASS = "android:app:Application"
	
	final lazy val APPLICATION_ONCREATE = "onCreate:()V"
	final lazy val APPLICATION_ONTERMINATE = "onTerminate()V"
	  
	final lazy val ACTIVITY_ONCREATE = "onCreate:(Landroid/os/Bundle;)V"
	final lazy val ACTIVITY_ONSTART = "onStart:()V"
	final lazy val ACTIVITY_ONRESTOREINSTANCESTATE = "onRestoreInstanceState:(Landroid/os/Bundle;)V"
	final lazy val ACTIVITY_ONPOSTCREATE = "onPostCreate:(Landroid/os/Bundle;)V"
	final lazy val ACTIVITY_ONRESUME = "onResume:()V"
	final lazy val ACTIVITY_ONPOSTRESUME = "onPostResume:()V"
	final lazy val ACTIVITY_ONCREATEDESCRIPTION = "onCreateDescription:()Ljava/lang/CharSequence;"
	final lazy val ACTIVITY_ONSAVEINSTANCESTATE = "onSaveInstanceState:(Landroid/os/Bundle;)V"
	final lazy val ACTIVITY_ONPAUSE = "onPause:()V"
	final lazy val ACTIVITY_ONSTOP = "onStop:()V"
	final lazy val ACTIVITY_ONRESTART = "onRestart:()V"
	final lazy val ACTIVITY_ONDESTROY = "onDestroy:()V"
	
	final lazy val SERVICE_ONCREATE = "onCreate:()V"
	final lazy val SERVICE_ONSTART1 = "onStart:(Landroid/content/Intent;I)V"
	final lazy val SERVICE_ONSTART2 = "onStartCommand:(Landroid/content/Intent;II)I"
	final lazy val SERVICE_ONBIND = "onBind:(Landroid/content/Intent;)Landroid/os/IBinder;"
	final lazy val SERVICE_ONREBIND = "onRebind:(Landroid/content/Intent;)V"
	final lazy val SERVICE_ONUNBIND = "onUnbind:(Landroid/content/Intent;)Z"
	final lazy val SERVICE_ONDESTROY = "onDestroy:()V"
	
	final lazy val BROADCAST_ONRECEIVE = "onReceive:(Landroid/content/Context;Landroid/content/Intent;)V"
	
	final lazy val CONTENTPROVIDER_ONCREATE = "onCreate:()Z"
	
	final lazy val INTENT_NAME = "android.content.Intent"
	final lazy val ACTIVITY_SETINTENT_SIG = new Signature("Landroid/app/Activity;.setIntent:(Landroid/content/Intent;)V")

	final lazy val ASYNCTASK_ONPREEXECUTE = "onPreExecute:()V"
	final lazy val ASYNCTASK_DOINBACKGROUND = "doInBackground:([Ljava/lang/Object;)Ljava/lang/Object;"
	final lazy val ASYNCTASK_ONPROGRESSUPDATE = "onProgressUpdate:([Ljava/lang/Object;)V"
	final lazy val ASYNCTASK_ONPOSTEXECUTE = "onPostExecute:(Ljava/lang/Object;)V"

	private final lazy val applicationMethods = List(APPLICATION_ONCREATE, APPLICATION_ONTERMINATE)
	private final lazy val activityMethods = List(ACTIVITY_ONCREATE, ACTIVITY_ONDESTROY, ACTIVITY_ONPAUSE,
		ACTIVITY_ONRESTART, ACTIVITY_ONRESUME, ACTIVITY_ONSTART, ACTIVITY_ONSTOP,
		ACTIVITY_ONSAVEINSTANCESTATE, ACTIVITY_ONRESTOREINSTANCESTATE,
		ACTIVITY_ONCREATEDESCRIPTION, ACTIVITY_ONPOSTCREATE, ACTIVITY_ONPOSTRESUME)
	private final lazy val serviceMethods = List(SERVICE_ONCREATE, SERVICE_ONDESTROY, SERVICE_ONSTART1,
		SERVICE_ONSTART2, SERVICE_ONBIND, SERVICE_ONREBIND, SERVICE_ONUNBIND)
	private final lazy val broadcastMethods = List(BROADCAST_ONRECEIVE)
	private final lazy val contentproviderMethods = List(CONTENTPROVIDER_ONCREATE)
	
	def getApplicationLifecycleMethods: List[String] = applicationMethods
	
	def getActivityLifecycleMethods: List[String] = activityMethods
	
	def getServiceLifecycleMethods: List[String] = serviceMethods
	
	def getBroadcastLifecycleMethods: List[String] = broadcastMethods
	
	def getContentproviderLifecycleMethods: List[String] = contentproviderMethods
}
