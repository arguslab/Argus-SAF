/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core

import org.argus.jawa.core.util.IList

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object AndroidConstants {
  
  object CompType extends Enumeration {
    val ACTIVITY, SERVICE, RECEIVER, PROVIDER = Value
  }
  
  final val MAINCOMP_ENV = "envMain"
  final val COMP_ENV = "env"
  final val MAINCOMP_ENV_SUBSIG = "envMain:(Landroid/content/Intent;)V"
  final val COMP_ENV_SUBSIG = "env:(Landroid/content/Intent;)V"
  
  //following is standard intent actions
  final val ACTION_MAIN = "android.intent.action.MAIN"
  final val ACTION_MANAGE_NETWORK_USAGE = "android.intent.action.MANAGE_NETWORK_USAGE"
	  
	//following is standard intent categories
  final val CATEGORY_LAUNCHER = "android.intent.category.LAUNCHER"
	  
	//following are android ICC calls
	final val START_SERVICE = "startService:(Landroid/content/Intent;)Landroid/content/ComponentName;"
	final val BIND_SERVICE = "bindService:(Landroid/content/Intent;Landroid/content/ServiceConnection;I)Z"
	final val START_ACTIVITY = "startActivity:(Landroid/content/Intent;)V"
	final val START_ACTIVITY_BUND = "startActivity:(Landroid/content/Intent;Landroid/os/Bundle;)V"
	final val START_ACTIVITY_RESULT = "startActivityForResult:(Landroid/content/Intent;I)V"
	final val START_ACTIVITY_RESULT_BUND = "startActivityForResult:(Landroid/content/Intent;ILandroid/os/Bundle;)V"
	final val SEND_BROADCAST = "sendBroadcast:(Landroid/content/Intent;)V"
	final val SEND_BROADCAST_PERM = "sendBroadcast:(Landroid/content/Intent;Ljava/lang/String;)V"
	final val SEND_BROADCAST_AS_USER = "sendBroadcastAsUser:(Landroid/content/Intent;Landroid/os/UserHandle;)V"
	final val SEND_BROADCAST_AS_USER_PERM = "sendBroadcastAsUser:(Landroid/content/Intent;Landroid/os/UserHandle;Ljava/lang/String;)V"
	final val SEND_ORDERED_BROADCAST = "sendOrderedBroadcast:(Landroid/content/Intent;Ljava/lang/String;)V"
	final val SEND_ORDERED_BROADCAST_SEVEN_PARM = "sendOrderedBroadcast:(Landroid/content/Intent;Ljava/lang/String;Landroid/content/BroadcastReceiver;Landroid/os/Handler;ILjava/lang/String;Landroid/os/Bundle;)V"
	final val SEND_ORDERED_BROADCAST_AS_USER = "sendOrderedBroadcastAsUser:(Landroid/content/Intent;Landroid/os/UserHandle;Ljava/lang/String;Landroid/content/BroadcastReceiver;Landroid/os/Handler;ILjava/lang/String;Landroid/os/Bundle;)V"
	final val SEND_STICKY_BROADCAST = "sendStickyBroadcast:(Landroid/content/Intent;)V"
	final val SEND_STICKY_BROADCAST_AS_USER = "sendStickyBroadcastAsUser:(Landroid/content/Intent;Landroid/os/UserHandle;)V"
	final val SEND_STICKY_ORDERED_BROADCAST = "sendStickyOrderedBroadcast:(Landroid/content/Intent;Landroid/content/BroadcastReceiver;Landroid/os/Handler;ILjava/lang/String;Landroid/os/Bundle;)V"
	final val SEND_STICKY_ORDERED_BROADCAST_AS_USER = "sendStickyOrderedBroadcastAsUser:(Landroid/content/Intent;Landroid/os/UserHandle;Landroid/content/BroadcastReceiver;Landroid/os/Handler;ILjava/lang/String;Landroid/os/Bundle;)V"
	final val REGISTER_RECEIVER1 = "registerReceiver:(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;"
	final val	REGISTER_RECEIVER2 = "registerReceiver:(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;"

	private final def iccMethods_forResult = Set(START_ACTIVITY_RESULT, START_ACTIVITY_RESULT_BUND)
  private final def iccMethods_activity = Set(START_ACTIVITY, START_ACTIVITY_BUND) ++ iccMethods_forResult
  private final def iccMethods_service = Set(START_SERVICE, BIND_SERVICE)
  private final def iccMethods_receiver = Set(SEND_BROADCAST, SEND_BROADCAST_PERM, SEND_BROADCAST_AS_USER, SEND_BROADCAST_AS_USER_PERM,
      SEND_ORDERED_BROADCAST, SEND_ORDERED_BROADCAST_SEVEN_PARM, SEND_ORDERED_BROADCAST_AS_USER,
      SEND_STICKY_BROADCAST, SEND_STICKY_BROADCAST_AS_USER, SEND_STICKY_ORDERED_BROADCAST,
      SEND_STICKY_ORDERED_BROADCAST_AS_USER)
  
	private final def iccMethods = iccMethods_activity ++ iccMethods_service ++ iccMethods_receiver
	def getIccMethods: Set[String] = iccMethods
	def isStartActivityForResultMethod(subSig: String): Boolean = iccMethods_forResult.contains(subSig)
  def isActivityIccMethod(subSig: String): Boolean = iccMethods_activity.contains(subSig)
  def isServiceIccMethod(subSig: String): Boolean = iccMethods_service.contains(subSig)
  def isReceiverIccMethod(subSig: String): Boolean = iccMethods_receiver.contains(subSig)
  def isProviderIccMethod(subSig: String): Boolean = false
  def isIccMethod(subSig: String): Boolean = iccMethods.contains(subSig)

	final val SET_RESULT = "setResult:(I)V"
	final val SET_RESULT_INTENT = "setResult:(ILandroid/content/Intent;)V"

	private final def activitySetResultMethods = Set(SET_RESULT, SET_RESULT_INTENT)
	def isSetResult(subSig: String): Boolean = activitySetResultMethods.contains(subSig)

  def getIccCallType(calleeSubsig: String): AndroidConstants.CompType.Value = calleeSubsig match {
    case m if AndroidConstants.isActivityIccMethod(m) => AndroidConstants.CompType.ACTIVITY
    case m if AndroidConstants.isServiceIccMethod(m) => AndroidConstants.CompType.SERVICE
    case m if AndroidConstants.isReceiverIccMethod(m) => AndroidConstants.CompType.RECEIVER
    case m if AndroidConstants.isProviderIccMethod(m) => AndroidConstants.CompType.PROVIDER
    case a => throw new RuntimeException("unexpected ICC method: " + a)
  }
  
	def getDynRegisterMethods: IList[String] = List(REGISTER_RECEIVER1, REGISTER_RECEIVER2)
	
	final val INTENT = "android.content.Intent"
	final val INTENT_COMPONENT = "android.content.Intent.mComponent"
	final val INTENT_ACTION  = "android.content.Intent.mAction"
	final val INTENT_MTYPE  = "android.content.Intent.mType"
	final val INTENT_URI_DATA = "android.content.Intent.mData"
	final val INTENT_CATEGORIES = "android.content.Intent.mCategories"
	final val INTENT_EXTRAS = "android.content.Intent.mExtras"
	final val INTENT_PACKAGE = "android.content.Intent.mPackage"
	  
	final val INTENTFILTER = "android.content.IntentFilter"
	final val INTENTFILTER_ACTIONS  = "android.content.IntentFilter.mActions"
	final val INTENTFILTER_CATEGORIES = "android.content.IntentFilter.mCategories"
	  
	final val COMPONENTNAME = "android.content.ComponentName"
	final val COMPONENTNAME_PACKAGE = "android.content.ComponentName.mPackage"
	final val COMPONENTNAME_CLASS = "android.content.ComponentName.mClass"
	final val URI_STRING_URI = "android.net.Uri$StringUri"
	final val URI_STRING_URI_URI_STRING = "android.net.Uri$StringUri.uriString"  
	  
	final val ACTIVITY_FINDVIEWBYID = "Landroid/app/Activity;.findViewById:(I)Landroid/view/View;"
	final val VIEW_FINDVIEWBYID = "Landroid/view/View;.findViewById:(I)Landroid/view/View;"
	  
	final val SETCONTENTVIEW = "setContentView:(I)V"
	final val ACTIVITY = "android.app.Activity"
  final val SERVICE = "android.app.Service"
  final val RECEIVER = "android.content.BroadcastReceiver"
  final val PROVIDER = "android.content.ContentProvider"
	final val ACTIVITY_INTENT = "android.app.Activity.mIntent"
	  
	final val BUNDLE = "android.os.Bundle"
	  
	final val CONTEXT = "android.content.Context"
	final val CONTEXT_WRAPPER = "android.content.ContextWrapper"
	  
	final val ACCESSIBILITY_SERVICE = "accessibility"
  final val ACCOUNT_SERVICE = "account"
  final val ACTIVITY_SERVICE = "activity"
  final val ALARM_SERVICE = "alarm" 
  final val APPWIDGET_SERVICE = "appwidget"
  final val AUDIO_SERVICE = "audio"
  final val BACKUP_SERVICE = "backup"
  final val BLUETOOTH_SERVICE = "bluetooth"
  final val CLIPBOARD_SERVICE = "clipboard"
  final val CONNECTIVITY_SERVICE = "connectivity"
  final val COUNTRY_DETECTOR = "country_detector"
  final val DEVICE_POLICY_SERVICE = "device_policy"
  final val DISPLAY_SERVICE = "display"
  final val DOWNLOAD_SERVICE = "download"
  final val DROPBOX_SERVICE = "dropbox"
  final val INPUT_METHOD_SERVICE = "input_method"
  final val INPUT_SERVICE = "input"
  final val KEYGUARD_SERVICE = "keyguard"
  final val LAYOUT_INFLATER_SERVICE = "layout_inflater"
  final val LOCATION_SERVICE = "location"
  final val MEDIA_ROUTER_SERVICE = "media_router"
  final val NETWORKMANAGEMENT_SERVICE = "network_management"
  final val NETWORK_POLICY_SERVICE = "netpolicy"
  final val NETWORK_STATS_SERVICE = "netstats"
  final val NFC_SERVICE = "nfc"
  final val NOTIFICATION_SERVICE = "notification"
  final val NSD_SERVICE = "servicediscovery"
  final val POWER_SERVICE = "power"
  final val SCHEDULING_POLICY_SERVICE = "scheduling_policy"
  final val SEARCH_SERVICE = "search"
  final val SENSOR_SERVICE = "sensor"
  final val SERIAL_SERVICE = "serial"
  final val SIP_SERVICE = "sip"
  final val STATUS_BAR_SERVICE = "statusbar"
  final val STORAGE_SERVICE = "storage" 
  final val TELEPHONY_SERVICE = "phone"
  final val TEXT_SERVICES_MANAGER_SERVICE = "textservices"
  final val THROTTLE_SERVICE = "throttle"
  final val UI_MODE_SERVICE = "uimode"
  final val UPDATE_LOCK_SERVICE = "updatelock"
  final val USB_SERVICE = "usb"
  final val USER_SERVICE = "user"
  final val VIBRATOR_SERVICE = "vibrator"
  final val WALLPAPER_SERVICE = "wallpaper"
  final val WIFI_P2P_SERVICE = "wifip2p"
  final val WIFI_SERVICE = "wifi"
  final val WINDOW_SERVICE = "window"
  private val systemServiceStrings = 
    List(
    	ACCESSIBILITY_SERVICE,
		  ACCOUNT_SERVICE,
		  ACTIVITY_SERVICE,
		  ALARM_SERVICE,
		  APPWIDGET_SERVICE,
		  AUDIO_SERVICE,
		  BACKUP_SERVICE,
		  BLUETOOTH_SERVICE,
		  CLIPBOARD_SERVICE,
		  CONNECTIVITY_SERVICE,
		  COUNTRY_DETECTOR,
		  DEVICE_POLICY_SERVICE,
		  DISPLAY_SERVICE,
		  DOWNLOAD_SERVICE ,
		  DROPBOX_SERVICE,
		  INPUT_METHOD_SERVICE,
		  INPUT_SERVICE,
		  KEYGUARD_SERVICE,
		  LAYOUT_INFLATER_SERVICE,
		  LOCATION_SERVICE,
		  MEDIA_ROUTER_SERVICE,
		  NETWORKMANAGEMENT_SERVICE,
		  NETWORK_POLICY_SERVICE,
		  NETWORK_STATS_SERVICE,
		  NFC_SERVICE,
		  NOTIFICATION_SERVICE,
		  NSD_SERVICE,
		  POWER_SERVICE,
		  SCHEDULING_POLICY_SERVICE,
		  SEARCH_SERVICE,
		  SENSOR_SERVICE,
		  SERIAL_SERVICE,
		  SIP_SERVICE,
		  STATUS_BAR_SERVICE,
		  STORAGE_SERVICE, 
		  TELEPHONY_SERVICE,
		  TEXT_SERVICES_MANAGER_SERVICE,
		  THROTTLE_SERVICE,
		  UI_MODE_SERVICE,
		  UPDATE_LOCK_SERVICE,
		  USB_SERVICE,
		  USER_SERVICE,
		  VIBRATOR_SERVICE,
		  WALLPAPER_SERVICE,
		  WIFI_P2P_SERVICE,
		  WIFI_SERVICE,
		  WINDOW_SERVICE  
    )
	def getSystemServiceStrings: List[String] = this.systemServiceStrings
	
  // dependency libs
  final val MAVEN_SUPPORT_V4 = "support-v4"   //$NON-NLS-1$
  final val MAVEN_SUPPORT_V13 = "support-v13" //$NON-NLS-1$
  final val MAVEN_APPCOMPAT = "appcompat-v7"  //$NON-NLS-1$
	final val MAVEN_DESIGN = "design"
	final val MAVEN_SUPPORT_ANNOTATIONS = "support-annotations"
	final val MAVEN_CONSTRAINT_LAYOUT = "constraint-layout"
}
