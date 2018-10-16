/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
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
	final lazy val START_SERVICE = "startService:(Landroid/content/Intent;)Landroid/content/ComponentName;"
	final lazy val BIND_SERVICE = "bindService:(Landroid/content/Intent;Landroid/content/ServiceConnection;I)Z"
	final lazy val START_ACTIVITY = "startActivity:(Landroid/content/Intent;)V"
	final lazy val START_ACTIVITY_BUND = "startActivity:(Landroid/content/Intent;Landroid/os/Bundle;)V"
	final lazy val START_ACTIVITY_RESULT = "startActivityForResult:(Landroid/content/Intent;I)V"
	final lazy val START_ACTIVITY_RESULT_BUND = "startActivityForResult:(Landroid/content/Intent;ILandroid/os/Bundle;)V"
	final lazy val SEND_BROADCAST = "sendBroadcast:(Landroid/content/Intent;)V"
	final lazy val SEND_BROADCAST_PERM = "sendBroadcast:(Landroid/content/Intent;Ljava/lang/String;)V"
	final lazy val SEND_BROADCAST_AS_USER = "sendBroadcastAsUser:(Landroid/content/Intent;Landroid/os/UserHandle;)V"
	final lazy val SEND_BROADCAST_AS_USER_PERM = "sendBroadcastAsUser:(Landroid/content/Intent;Landroid/os/UserHandle;Ljava/lang/String;)V"
	final lazy val SEND_ORDERED_BROADCAST = "sendOrderedBroadcast:(Landroid/content/Intent;Ljava/lang/String;)V"
	final lazy val SEND_ORDERED_BROADCAST_SEVEN_PARM = "sendOrderedBroadcast:(Landroid/content/Intent;Ljava/lang/String;Landroid/content/BroadcastReceiver;Landroid/os/Handler;ILjava/lang/String;Landroid/os/Bundle;)V"
	final lazy val SEND_ORDERED_BROADCAST_AS_USER = "sendOrderedBroadcastAsUser:(Landroid/content/Intent;Landroid/os/UserHandle;Ljava/lang/String;Landroid/content/BroadcastReceiver;Landroid/os/Handler;ILjava/lang/String;Landroid/os/Bundle;)V"
	final lazy val SEND_STICKY_BROADCAST = "sendStickyBroadcast:(Landroid/content/Intent;)V"
	final lazy val SEND_STICKY_BROADCAST_AS_USER = "sendStickyBroadcastAsUser:(Landroid/content/Intent;Landroid/os/UserHandle;)V"
	final lazy val SEND_STICKY_ORDERED_BROADCAST = "sendStickyOrderedBroadcast:(Landroid/content/Intent;Landroid/content/BroadcastReceiver;Landroid/os/Handler;ILjava/lang/String;Landroid/os/Bundle;)V"
	final lazy val SEND_STICKY_ORDERED_BROADCAST_AS_USER = "sendStickyOrderedBroadcastAsUser:(Landroid/content/Intent;Landroid/os/UserHandle;Landroid/content/BroadcastReceiver;Landroid/os/Handler;ILjava/lang/String;Landroid/os/Bundle;)V"
	final lazy val REGISTER_RECEIVER1 = "registerReceiver:(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;"
	final lazy val REGISTER_RECEIVER2 = "registerReceiver:(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;"

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

	final lazy val SET_RESULT = "setResult:(I)V"
	final lazy val SET_RESULT_INTENT = "setResult:(ILandroid/content/Intent;)V"

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

  final lazy val COMPONENT_NAME = "android.content.ComponentName"
  final lazy val COMPONENT_NAME_CLASS = "mClass"

	final lazy val INTENT = "android.content.Intent"
	final lazy val INTENT_COMPONENT = "mComponent"
	final lazy val INTENT_ACTION  = "mAction"
	final lazy val INTENT_MTYPE  = "mType"
	final lazy val URI = "android.net.Uri"
  final lazy val URI_STRING = "uri"
	final lazy val INTENT_URI_DATA = "mData"
	final lazy val INTENT_CATEGORIES = "mCategories"
  final lazy val BUNDLE = "android.os.Bundle"
  final lazy val BUNDLE_ENTRIES = "entries"
	final lazy val INTENT_EXTRAS = "mExtras"
	final lazy val INTENT_PACKAGE = "mPackage"
	  
	final lazy val INTENT_FILTER = "android.content.IntentFilter"
	final lazy val INTENT_FILTER_ACTIONS  = "mActions"
	final lazy val INTENT_FILTER_CATEGORIES = "mCategories"
	  
	final lazy val ACTIVITY_FINDVIEWBYID = "Landroid/app/Activity;.findViewById:(I)Landroid/view/View;"
	final lazy val VIEW_FINDVIEWBYID = "Landroid/view/View;.findViewById:(I)Landroid/view/View;"
	  
	final lazy val SETCONTENTVIEW = "setContentView:(I)V"
	final lazy val ACTIVITY = "android.app.Activity"
  final lazy val SERVICE = "android.app.Service"
  final lazy val RECEIVER = "android.content.BroadcastReceiver"
  final lazy val PROVIDER = "android.content.ContentProvider"
	final lazy val ACTIVITY_INTENT = "mIntent"
	  
	final lazy val CONTEXT = "android.content.Context"
	final lazy val CONTEXT_WRAPPER = "android.content.ContextWrapper"
	  
	final lazy val ACCESSIBILITY_SERVICE = "accessibility"
  final lazy val ACCOUNT_SERVICE = "account"
  final lazy val ACTIVITY_SERVICE = "activity"
  final lazy val ALARM_SERVICE = "alarm"
  final lazy val APPWIDGET_SERVICE = "appwidget"
  final lazy val AUDIO_SERVICE = "audio"
  final lazy val BACKUP_SERVICE = "backup"
  final lazy val BLUETOOTH_SERVICE = "bluetooth"
  final lazy val CLIPBOARD_SERVICE = "clipboard"
  final lazy val CONNECTIVITY_SERVICE = "connectivity"
  final lazy val COUNTRY_DETECTOR = "country_detector"
  final lazy val DEVICE_POLICY_SERVICE = "device_policy"
  final lazy val DISPLAY_SERVICE = "display"
  final lazy val DOWNLOAD_SERVICE = "download"
  final lazy val DROPBOX_SERVICE = "dropbox"
  final lazy val INPUT_METHOD_SERVICE = "input_method"
  final lazy val INPUT_SERVICE = "input"
  final lazy val KEYGUARD_SERVICE = "keyguard"
  final lazy val LAYOUT_INFLATER_SERVICE = "layout_inflater"
  final lazy val LOCATION_SERVICE = "location"
  final lazy val MEDIA_ROUTER_SERVICE = "media_router"
  final lazy val NETWORKMANAGEMENT_SERVICE = "network_management"
  final lazy val NETWORK_POLICY_SERVICE = "netpolicy"
  final lazy val NETWORK_STATS_SERVICE = "netstats"
  final lazy val NFC_SERVICE = "nfc"
  final lazy val NOTIFICATION_SERVICE = "notification"
  final lazy val NSD_SERVICE = "servicediscovery"
  final lazy val POWER_SERVICE = "power"
  final lazy val SCHEDULING_POLICY_SERVICE = "scheduling_policy"
  final lazy val SEARCH_SERVICE = "search"
  final lazy val SENSOR_SERVICE = "sensor"
  final lazy val SERIAL_SERVICE = "serial"
  final lazy val SIP_SERVICE = "sip"
  final lazy val STATUS_BAR_SERVICE = "statusbar"
  final lazy val STORAGE_SERVICE = "storage"
  final lazy val TELEPHONY_SERVICE = "phone"
  final lazy val TEXT_SERVICES_MANAGER_SERVICE = "textservices"
  final lazy val THROTTLE_SERVICE = "throttle"
  final lazy val UI_MODE_SERVICE = "uimode"
  final lazy val UPDATE_LOCK_SERVICE = "updatelock"
  final lazy val USB_SERVICE = "usb"
  final lazy val USER_SERVICE = "user"
  final lazy val VIBRATOR_SERVICE = "vibrator"
  final lazy val WALLPAPER_SERVICE = "wallpaper"
  final lazy val WIFI_P2P_SERVICE = "wifip2p"
  final lazy val WIFI_SERVICE = "wifi"
  final lazy val WINDOW_SERVICE = "window"
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
