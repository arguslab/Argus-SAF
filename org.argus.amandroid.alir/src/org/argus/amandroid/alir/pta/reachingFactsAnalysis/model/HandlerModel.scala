/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.pta.reachingFactsAnalysis.model

import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.PTAResult
import org.argus.jawa.alir.pta.reachingFactsAnalysis.RFAFact
import org.argus.jawa.core.{JawaClass, JawaMethod}
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object HandlerModel {
	def isHandler(r: JawaClass): Boolean = r.getName == "android.os.Handler"
	def doHandlerCall(s: PTAResult, p: JawaMethod, args: List[String], retVars: Seq[String], currentContext: Context): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
	  val newFacts = isetEmpty[RFAFact]
	  val delFacts = isetEmpty[RFAFact]
	  val byPassFlag = true
	  p.getSignature.signature match{
	    case "Landroid/os/Handler;.<init>:()V" =>  //public constructor
		  case "Landroid/os/Handler;.<init>:(Landroid/os/Handler$Callback;)V" =>  //public constructor
		  case "Landroid/os/Handler;.<init>:(Landroid/os/Handler$Callback;Z)V" =>  //public constructor
		  case "Landroid/os/Handler;.<init>:(Landroid/os/Looper;)V" =>  //public constructor
		  case "Landroid/os/Handler;.<init>:(Landroid/os/Looper;Landroid/os/Handler$Callback;)V" =>  //public constructor
		  case "Landroid/os/Handler;.<init>:(Landroid/os/Looper;Landroid/os/Handler$Callback;Z)V" =>  //public constructor
		  case "Landroid/os/Handler;.<init>:(Z)V" =>  //public constructor
		  case "Landroid/os/Handler;.dispatchMessage:(Landroid/os/Message;)V" =>  //public
		  case "Landroid/os/Handler;.dump:(Landroid/util/Printer;Ljava/lang/String;)V" =>  //public final
		  case "Landroid/os/Handler;.enqueueMessage:(Landroid/os/MessageQueue;Landroid/os/Message;J)Z" =>  //private
		  case "Landroid/os/Handler;.getIMessenger:()Landroid/os/IMessenger;" =>  //final
		  case "Landroid/os/Handler;.getLooper:()Landroid/os/Looper;" =>  //public final
		  case "Landroid/os/Handler;.getMessageName:(Landroid/os/Message;)Ljava/lang/String;" =>  //public
		  case "Landroid/os/Handler;.getPostMessage:(Ljava/lang/Runnable;)Landroid/os/Message;" =>  //private static
		  case "Landroid/os/Handler;.getPostMessage:(Ljava/lang/Runnable;Ljava/lang/Object;)Landroid/os/Message;" =>  //private static
		  case "Landroid/os/Handler;.handleCallback:(Landroid/os/Message;)V" =>  //private static
		  case "Landroid/os/Handler;.handleMessage:(Landroid/os/Message;)V" =>  //public
		  case "Landroid/os/Handler;.hasCallbacks:(Ljava/lang/Runnable;)Z" =>  //public final
		  case "Landroid/os/Handler;.hasMessages:(I)Z" =>  //public final
		  case "Landroid/os/Handler;.hasMessages:(ILjava/lang/Object;)Z" =>  //public final
		  case "Landroid/os/Handler;.obtainMessage:()Landroid/os/Message;" =>  //public final
		  case "Landroid/os/Handler;.obtainMessage:(I)Landroid/os/Message;" =>  //public final
		  case "Landroid/os/Handler;.obtainMessage:(III)Landroid/os/Message;" =>  //public final
		  case "Landroid/os/Handler;.obtainMessage:(IIILjava/lang/Object;)Landroid/os/Message;" =>  //public final
		  case "Landroid/os/Handler;.obtainMessage:(ILjava/lang/Object;)Landroid/os/Message;" =>  //public final
		  case "Landroid/os/Handler;.post:(Ljava/lang/Runnable;)Z" =>  //public final
		  case "Landroid/os/Handler;.postAtFrontOfQueue:(Ljava/lang/Runnable;)Z" =>  //public final
		  case "Landroid/os/Handler;.postAtTime:(Ljava/lang/Runnable;J)Z" =>  //public final
		  case "Landroid/os/Handler;.postAtTime:(Ljava/lang/Runnable;Ljava/lang/Object;J)Z" =>  //public final
		  case "Landroid/os/Handler;.postDelayed:(Ljava/lang/Runnable;J)Z" =>  //public final
		  case "Landroid/os/Handler;.removeCallbacks:(Ljava/lang/Runnable;)V" =>  //public final
		  case "Landroid/os/Handler;.removeCallbacks:(Ljava/lang/Runnable;Ljava/lang/Object;)V" =>  //public final
		  case "Landroid/os/Handler;.removeCallbacksAndMessages:(Ljava/lang/Object;)V" =>  //public final
		  case "Landroid/os/Handler;.removeMessages:(I)V" =>  //public final
		  case "Landroid/os/Handler;.removeMessages:(ILjava/lang/Object;)V" =>  //public final
		  case "Landroid/os/Handler;.runWithScissors:(Ljava/lang/Runnable;J)Z" =>  //public final
		  case "Landroid/os/Handler;.sendEmptyMessage:(I)Z" =>  //public final
		  case "Landroid/os/Handler;.sendEmptyMessageAtTime:(IJ)Z" =>  //public final
		  case "Landroid/os/Handler;.sendEmptyMessageDelayed:(IJ)Z" =>  //public final
		  case "Landroid/os/Handler;.sendMessage:(Landroid/os/Message;)Z" =>  //public final
		  case "Landroid/os/Handler;.sendMessageAtFrontOfQueue:(Landroid/os/Message;)Z" =>  //public final
		  case "Landroid/os/Handler;.sendMessageAtTime:(Landroid/os/Message;J)Z" =>  //public
		  case "Landroid/os/Handler;.sendMessageDelayed:(Landroid/os/Message;J)Z" =>  //public final
		  case "Landroid/os/Handler;.toString:()Ljava/lang/String;" =>  //public
		  case _ =>
	  }
	  (newFacts, delFacts, byPassFlag)
	}
}
