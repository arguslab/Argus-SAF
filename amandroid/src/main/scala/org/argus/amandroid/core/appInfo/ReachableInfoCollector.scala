/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.appInfo

import org.argus.amandroid.core.AndroidConstants
import org.argus.amandroid.core.parser.LayoutControl
import org.argus.amandroid.core.codegen.AndroidEntryPointConstants
import org.argus.jawa.flow.reachability.ReachabilityAnalysis
import org.argus.jawa.flow.util.ExplicitValueFinder
import org.argus.jawa.core.ast.CallStatement
import org.argus.jawa.core._
import org.argus.jawa.core.elements.{JawaType, Signature}
import org.argus.jawa.core.util._


/**
 * Analyzes the classes in the APK file to find custom implementations of the
 * well-known Android callback and handler interfaces.
 * 
 * Adapted Steven Arzt (FlowDroid) 's equivalent code
 *
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author Sankardas Roy. 
 */
class ReachableInfoCollector(val global: Global, entryPointTypes: ISet[JawaType]) {
  final val TITLE = "ReachableInfoCollector"
  private final val callbackMethods: MMap[JawaType, MSet[Signature]] = mmapEmpty // a map from an app component to associated callbacks
  private final val layoutClasses: MMap[JawaType, MSet[Int]] = mmapEmpty
  private final val androidCallbacks: MSet[String] = msetEmpty  // a list of system interfaces which have wellknown callback methods

  def getCallbackMethods: IMap[JawaType, ISet[Signature]] = this.callbackMethods.map {
    case (k, vs) => k -> vs.toSet
  }.toMap
  def getLayoutClasses: IMap[JawaType, Set[Int]] = this.layoutClasses.map {
    case (k, vs) => k -> vs.toSet
  }.toMap

  private var reachableMap: IMap[JawaType, ISet[Signature]] = imapEmpty // a map from an app component to the reachable methods

  def getReachableMap: IMap[JawaType, ISet[Signature]] = this.reachableMap

  initAndroidCallbacks
  
  def init(): Unit = {
    reachableMap = ReachabilityAnalysis.getReachableMethodsByCHA(global, entryPointTypes)
  }

  def getSensitiveLayoutContainer(layoutControls: IMap[Int, LayoutControl]): Set[JawaType] = {
    val result: MSet[JawaType] = msetEmpty
    layoutControls.foreach{
      case (i, lc) =>
        if(lc.isSensitive){
          reachableMap.foreach{
            case (r, ps) =>
              if(ps.exists(p => global.getMethodOrResolve(p).exists(_.retrieveCode.contains(i.toString))))
                result += r
          }
        }
    }
    result.toSet
  }

  def getSensitiveAPIContainer(apiSig: String): ISet[JawaType] = {
    val result: MSet[JawaType] = msetEmpty
      reachableMap.foreach{
        case (r, ps) =>
          if(ps.exists(p => global.getMethodOrResolve(p).exists(_.retrieveCode.contains(apiSig))))
            result += r
      }
    result.toSet
  }

  def getInterestingStringContainer(str: String): ISet[JawaType] = {
    val result: MSet[JawaType] = msetEmpty
    reachableMap.foreach{
      case (r, ps) =>
        if(ps.exists(p => global.getMethodOrResolve(p).exists(_.retrieveCode.contains(str))))
          result += r
    }
    result.toSet
  }

  /**
   * Collects the callback methods for all Android default handlers
   * implemented in the source code.
   *
   */
  def collectCallbackMethods(): Unit = {
    global.reporter.println("Collecting callback methods in layout mappings...")
    findClassLayoutMappings()
    global.reporter.println("Collecting callback methods in app source...")
    collectCallbackMethodsInAppSource()
    global.reporter.echo(TITLE, "current all callbacks = " + this.callbackMethods)
  }
  
  /**
   * Finds the mappings between classes and their respective layout files
   */
  def findClassLayoutMappings(): Unit = {
    this.entryPointTypes.foreach{ compTyp =>
      global.getClazz(compTyp) match {
        case Some(c) if c.isConcrete && !c.isSystemLibraryClass =>
          c.getDeclaredMethods.foreach { method =>
            if(method.isConcrete){
              method.getBody.resolvedBody.locations foreach { l =>
                l.statement match {
                  case j: CallStatement =>
                    val sig = j.signature
                    if (sig.getSubSignature == AndroidConstants.SETCONTENTVIEW) {
                      val nums = ExplicitValueFinder.findExplicitLiteralForArgs(method, l, j.arg(0)).filter(_.isInt)
                      val declType = sig.getClassType
                      this.layoutClasses.getOrElseUpdate(declType, msetEmpty) ++= nums.map(_.getInt)
                    }
                  case _ =>
                }
              }
            }
          }
        case _ =>
      }
    }
  }

  /**
    * Analyzes the given class to find callback methods
    */
  private def collectCallbackMethodsInAppSource(): Unit = {
    // Check for callback handlers implemented via interfaces
    this.reachableMap.foreach { case (lifecycleElement, sigs) =>
      analyzeReachableMethods(sigs, lifecycleElement)
    }
    this.reachableMap.map { case (lifecycleElement, sigs) =>
      lifecycleElement -> sigs.map(_.classTyp)
    }.foreach { case (lifecycleElement, typs) =>
      // Check for method overrides
      typs.foreach { typ =>
        global.getClazz(typ) match {
          case Some(clazz) => analyzeMethodOverrideCallbacks(clazz, lifecycleElement)
          case None =>
        }
      }
    }
  }

  /**
   * Enumeration for the types of classes we can have
   */
  object ClassType extends Enumeration {
    val Activity,
    Service,
    BroadcastReceiver,
    ContentProvider,
    Plain = Value
  }

  private def analyzeMethodOverrideCallbacks(record: JawaClass, lifecycleElement: JawaType): Unit = {
    if (!record.isConcrete)
      return
  
    // There are also some classes that implement interesting callback methods.
    // We model this as follows: Whenever the user overwrites a method in an
    // Android OS class that is not a well-known lifecycle method, we treat
    // it as a potential callback.
    var classType = ClassType.Plain
    val systemMethods: MSet[String] = msetEmpty
    for (ancestorClass <- global.getClassHierarchy.getAllSuperClassesOf(record)) {
      if (ancestorClass.getName.equals(AndroidEntryPointConstants.ACTIVITY_CLASS))
        classType = ClassType.Activity
      else if (ancestorClass.getName.equals(AndroidEntryPointConstants.SERVICE_CLASS))
        classType = ClassType.Service
      else if (ancestorClass.getName.equals(AndroidEntryPointConstants.BROADCAST_RECEIVER_CLASS))
        classType = ClassType.BroadcastReceiver
      else if (ancestorClass.getName.equals(AndroidEntryPointConstants.CONTENT_PROVIDER_CLASS))
        classType = ClassType.ContentProvider
  
      if (ancestorClass.getName.startsWith("android."))
        for (procedure <- ancestorClass.getDeclaredMethods)
          if (!procedure.isConstructor){
            systemMethods.add(procedure.getSubSignature)
          }
    }
  
    var lifecycleFlag = false // represents if a method is lifecycle method
    // Iterate over all user-implemented methods. If they are inherited
    // from a system class, they are callback candidates.
    for (sClass <- global.getClassHierarchy.getAllSubClassesOfIncluding(record)) {
      val rName = sClass.getName
      if (!rName.startsWith("android.") && !rName.startsWith("com.android."))
        for (procedure <- sClass.getDeclaredMethods) {
          if(!procedure.isStatic){ // static method cannot be overridden
            lifecycleFlag = false
            if (systemMethods.contains(procedure.getSubSignature)){
              // This is an overridden system method. Check that we don't have
              // one of the lifecycle methods as they are treated separately.
              if (classType == ClassType.Activity
                && AndroidEntryPointConstants.getActivityLifecycleMethods.contains(procedure.getSubSignature))
                lifecycleFlag = true
              if (classType == ClassType.Service
                && AndroidEntryPointConstants.getServiceLifecycleMethods.contains(procedure.getSubSignature))
                lifecycleFlag = true
              if (classType == ClassType.BroadcastReceiver
                && AndroidEntryPointConstants.getBroadcastLifecycleMethods.contains(procedure.getSubSignature))
                lifecycleFlag = true
              if (classType == ClassType.ContentProvider
                && AndroidEntryPointConstants.getContentproviderLifecycleMethods.contains(procedure.getSubSignature))
                lifecycleFlag = true
              if(!lifecycleFlag){
                checkAndAddMethod(procedure, lifecycleElement) // This is a real callback method
              }
            }
          }
        }
    }
  }

  private def analyzeReachableMethods(sigs: ISet[Signature], lifecycleElement: JawaType): Unit = {
    sigs.foreach{ sig =>
      analyzeMethodForCallbackRegistrations(sig, lifecycleElement)
    }
  }

  private def analyzeMethodForCallbackRegistrations(sig: Signature, lifecycleElement: JawaType): Unit = {
    val callbackClasses: MSet[JawaClass] = msetEmpty
    sig.getParameterTypes.foreach { param =>
      if(this.androidCallbacks.contains(param.baseTyp)) {
        val typRecOpt = global.getClazz(param)
        typRecOpt match {
          case Some(typRec) =>
            val hier = global.getClassHierarchy
            if (typRec.isInterface) {
              val impls = hier.getAllImplementersOf(typRec)
              if (impls.nonEmpty) {
                callbackClasses ++= impls.map { impl =>
                  hier.getAllSubClassesOfIncluding(impl)
                }.reduce(iunion[JawaClass])
              }
            } else {
              callbackClasses ++= hier.getAllSubClassesOfIncluding(typRec)
            }
          case None =>
        }
      }
    }

    callbackClasses.foreach{ rec =>
      analyzeClass(rec, lifecycleElement)
    }
  }

  private def analyzeClass(clazz: JawaClass, lifecycleElement: JawaType): Unit = {
    // Do not analyze system classes
    if (clazz.getName.startsWith("android.")|| clazz.getName.startsWith("com.android.") || clazz.getName.startsWith("java."))
      return
  
    // Check for callback handlers implemented via interfaces
    analyzeClassInterfaceCallbacks(clazz, clazz, lifecycleElement)
  }

  private def analyzeClassInterfaceCallbacks(baseClass: JawaClass, clazz: JawaClass, lifecycleElement: JawaType):Unit = {
    // We cannot create instances of abstract classes anyway, so there is no
    // reason to look for interface implementations
    if (!baseClass.isConcrete) {
      return
    }
  
    // For a first take, we consider all classes in the android.* packages
    // to be part of the operating system
    if (baseClass.getName.startsWith("android.") || baseClass.getName.startsWith("com.android.")) {
      return
    }
  
    // If we are a class, one of our superclasses might implement an Android
    // interface
    if (clazz.hasSuperClass) {
      analyzeClassInterfaceCallbacks(baseClass, clazz.getSuperClass, lifecycleElement) // recursion
    }
    // Do we implement one of the well-known interfaces?
    for (i <- collectAllInterfaces(clazz)) {
      if(this.androidCallbacks.contains(i.getName)){
        i.getDeclaredMethods.foreach{ proc =>
          getMethodFromHierarchy(baseClass, proc.getSubSignature).foreach { m =>
            checkAndAddMethod(m, lifecycleElement)
          }
        }
      }
    }
  }

  /**
   * Checks whether the given method comes from a system class. If not,
   * it is added to the list of callback methods.
    *
    * @param proc The method to check and add
   * @param lifecycleElement The component (activity, service, etc.) to which this
   * callback method belongs
   */
  private def checkAndAddMethod(proc: JawaMethod, lifecycleElement: JawaType) = {
    if(!proc.getFullName.startsWith("android.")){
      this.callbackMethods.getOrElseUpdate(lifecycleElement, msetEmpty) += proc.getSignature
    }
  }

  private def collectAllInterfaces(ar: JawaClass): ISet[JawaClass] = {
    if(ar.getInterfaceSize == 0) isetEmpty
    else ar.getInterfaces ++ ar.getInterfaces.flatMap{i => collectAllInterfaces(i)}
  }

  private def getMethodFromHierarchy(r: JawaClass, subSig: String): Option[JawaMethod] = {
    try {
      if (r.declaresMethod(subSig)) r.getMethod(subSig)
      else if (r.hasSuperClass) getMethodFromHierarchy(r.getSuperClass, subSig)
      else None
    } catch {
      case _: Exception =>
        None // Add this to tentatively avoid issue #22
    }
  }

  private def initAndroidCallbacks = {
  
    // java.lang.CharSequence
    this.androidCallbacks += "java.lang.CharSequence" // sankar adds it. note that it is not an android stuff so we need to move it somewhere else.
  
    this.androidCallbacks += "android.accounts.OnAccountsUpdateListener"

    // android.animation
    this.androidCallbacks += "android.animation.Animator$AnimatorListener"
    this.androidCallbacks += "android.animation.LayoutTransition$TransitionListener"
    this.androidCallbacks += "android.animation.TimeAnimator$TimeListener"
    this.androidCallbacks += "android.animation.ValueAnimator$AnimatorUpdateListener"
    // android.app
    this.androidCallbacks += "android.app.ActionBar$OnMenuVisibilityListener"
    this.androidCallbacks += "android.app.ActionBar$OnNavigationListener"
    this.androidCallbacks += "android.app.ActionBar$TabListener"
    this.androidCallbacks += "android.app.Application$ActivityLifecycleCallbacks"
    this.androidCallbacks += "android.app.DatePickerDialog$OnDateSetListener"
    this.androidCallbacks += "android.app.FragmentBreadCrumbs$OnBreadCrumbClickListener"
    this.androidCallbacks += "android.app.FragmentManager$OnBackStackChangedListener"
    this.androidCallbacks += "android.app.KeyguardManager$OnKeyguardExitResult"
    this.androidCallbacks += "android.app.LoaderManager$LoaderCallbacks"
    this.androidCallbacks += "android.app.PendingIntent$OnFinished"
    this.androidCallbacks += "android.app.SearchManager$OnCancelListener"
    this.androidCallbacks += "android.app.SearchManager$OnDismissListener"
    this.androidCallbacks += "android.app.TimePickerDialog$OnTimeSetListener"
    // android.bluetooth
    this.androidCallbacks += "android.bluetooth.BluetoothProfile$ServiceListener"
    // android.content
    this.androidCallbacks += "android.content.ClipboardManager$OnPrimaryClipChangedListener"
    this.androidCallbacks += "android.content.ComponentCallbacks"
    this.androidCallbacks += "android.content.ComponentCallbacks2"     
    this.androidCallbacks += "android.content.DialogInterface$OnCancelListener"
    this.androidCallbacks += "android.content.DialogInterface$OnClickListener"
    this.androidCallbacks += "android.content.DialogInterface$OnDismissListener"
    this.androidCallbacks += "android.content.DialogInterface$OnKeyListener"
    this.androidCallbacks += "android.content.DialogInterface$OnMultiChoiceClickListener"
    this.androidCallbacks += "android.content.DialogInterface$OnShowListener"
    this.androidCallbacks += "android.content.IntentSender$OnFinished"
    this.androidCallbacks += "android.content.Loader$OnLoadCanceledListener"
    this.androidCallbacks += "android.content.Loader$OnLoadCompleteListener"
    this.androidCallbacks += "android.content.SharedPreferences$OnSharedPreferenceChangeListener"
    this.androidCallbacks += "android.content.SyncStatusObserver"
    // android.database.Cursor
    this.androidCallbacks += "android.database.Cursor"  // sankar added
    // android.database.sqlite
    this.androidCallbacks += "android.database.sqlite.SQLiteTransactionListener"
    // android.drm
    this.androidCallbacks += "android.drm.DrmManagerClient$OnErrorListener"
    this.androidCallbacks += "android.drm.DrmManagerClient$OnEventListener"
    this.androidCallbacks += "android.drm.DrmManagerClient$OnInfoListener"
    // android.gesture      
    this.androidCallbacks += "android.gesture.GestureOverlayView$OnGestureListener"
    this.androidCallbacks += "android.gesture.GestureOverlayView$OnGesturePerformedListener"
    this.androidCallbacks += "android.gesture.GestureOverlayView$OnGesturingListener"
    // android.graphics
    this.androidCallbacks += "android.graphics.SurfaceTexture$OnFrameAvailableListener"
    // android.hardware
    this.androidCallbacks += "android.hardware.Camera$AutoFocusCallback"
    this.androidCallbacks += "android.hardware.Camera$AutoFocusMoveCallback"
    this.androidCallbacks += "android.hardware.Camera$ErrorCallback"
    this.androidCallbacks += "android.hardware.Camera$FaceDetectionListener"
    this.androidCallbacks += "android.hardware.Camera$OnZoomChangeListener"
    this.androidCallbacks += "android.hardware.Camera$PictureCallback"
    this.androidCallbacks += "android.hardware.Camera$PreviewCallback"
    this.androidCallbacks += "android.hardware.Camera$ShutterCallback"
    this.androidCallbacks += "android.hardware.SensorEventListener"
    // android.hardware.display
    this.androidCallbacks += "android.hardware.display.DisplayManager$DisplayListener"
    // android.hardware.input
    this.androidCallbacks += "android.hardware.input.InputManager$InputDeviceListener"
    // android.inputmethodservice
    this.androidCallbacks += "android.inputmethodservice.KeyboardView$OnKeyboardActionListener"
    // android.location
    this.androidCallbacks += "android.location.GpsStatus$Listener"
    this.androidCallbacks += "android.location.GpsStatus$NmeaListener"
    this.androidCallbacks += "android.location.LocationListener"
    // android.media
    this.androidCallbacks += "android.media.AudioManager$OnAudioFocusChangeListener"
    this.androidCallbacks += "android.media.AudioRecord$OnRecordPositionUpdateListener"
    this.androidCallbacks += "android.media.AudioRecord$OnRecordPositionUpdateListener"
    this.androidCallbacks += "android.media.JetPlayer$OnJetEventListener"
    this.androidCallbacks += "android.media.MediaPlayer$OnBufferingUpdateListener"
    this.androidCallbacks += "android.media.MediaPlayer$OnCompletionListener"
    this.androidCallbacks += "android.media.MediaPlayer$OnErrorListener"
    this.androidCallbacks += "android.media.MediaPlayer$OnInfoListener"
    this.androidCallbacks += "android.media.MediaPlayer$OnPreparedListener"
    this.androidCallbacks += "android.media.MediaPlayer$OnSeekCompleteListener"
    this.androidCallbacks += "android.media.MediaPlayer$OnTimedTextListener"
    this.androidCallbacks += "android.media.MediaPlayer$OnVideoSizeChangedListener"
    this.androidCallbacks += "android.media.MediaRecorder$OnErrorListener"
    this.androidCallbacks += "android.media.MediaRecorder$OnInfoListener"
    this.androidCallbacks += "android.media.MediaScannerConnection$MediaScannerConnectionClient"
    this.androidCallbacks += "android.media.MediaScannerConnection$OnScanCompletedListener"
    this.androidCallbacks += "android.media.SoundPool$OnLoadCompleteListener"
    // android.media.audiofx
    this.androidCallbacks += "android.media.audiofx.AudioEffect$OnControlStatusChangeListener"
    this.androidCallbacks += "android.media.audiofx.AudioEffect$OnEnableStatusChangeListener"
    this.androidCallbacks += "android.media.audiofx.BassBoost$OnParameterChangeListener"
    this.androidCallbacks += "android.media.audiofx.EnvironmentalReverb$OnParameterChangeListener"
    this.androidCallbacks += "android.media.audiofx.Equalizer$OnParameterChangeListener"
    this.androidCallbacks += "android.media.audiofx.PresetReverb$OnParameterChangeListener"
    this.androidCallbacks += "android.media.audiofx.Virtualizer$OnParameterChangeListener"
    this.androidCallbacks += "android.media.audiofx.Visualizer$OnDataCaptureListener"
    // android.media.effect
    this.androidCallbacks += "android.media.effect.EffectUpdateListener"
    // android.net.nsd
    this.androidCallbacks += "android.net.nsd.NsdManager$DiscoveryListener"
    this.androidCallbacks += "android.net.nsd.NsdManager$RegistrationListener"
    this.androidCallbacks += "android.net.nsd.NsdManager$ResolveListener"
    // android.net.sip
    this.androidCallbacks += "android.net.sip.SipRegistrationListener"
    // android.net.wifi.p2p
    this.androidCallbacks += "android.net.wifi.p2p.WifiP2pManager$ActionListener"
    this.androidCallbacks += "android.net.wifi.p2p.WifiP2pManager$ChannelListener"
    this.androidCallbacks += "android.net.wifi.p2p.WifiP2pManager$ConnectionInfoListener"
    this.androidCallbacks += "android.net.wifi.p2p.WifiP2pManager$DnsSdServiceResponseListener"
    this.androidCallbacks += "android.net.wifi.p2p.WifiP2pManager$DnsSdTxtRecordListener"
    this.androidCallbacks += "android.net.wifi.p2p.WifiP2pManager$GroupInfoListener"
    this.androidCallbacks += "android.net.wifi.p2p.WifiP2pManager$PeerListListener"
    this.androidCallbacks += "android.net.wifi.p2p.WifiP2pManager$ServiceResponseListener"
    this.androidCallbacks += "android.net.wifi.p2p.WifiP2pManager$UpnpServiceResponseListener"
    // android.os
    this.androidCallbacks += "android.os.CancellationSignal$OnCancelListener"
    this.androidCallbacks += "android.os.IBinder$DeathRecipient"
    this.androidCallbacks += "android.os.MessageQueue$IdleHandler"
    this.androidCallbacks += "android.os.RecoverySystem$ProgressListener"
    // android.preference
    this.androidCallbacks += "android.preference.Preference$OnPreferenceChangeListener"
    this.androidCallbacks += "android.preference.Preference$OnPreferenceClickListener"
    this.androidCallbacks += "android.preference.PreferenceFragment$OnPreferenceStartFragmentCallback"
    this.androidCallbacks += "android.preference.PreferenceManager$OnActivityDestroyListener"
    this.androidCallbacks += "android.preference.PreferenceManager$OnActivityResultListener"
    this.androidCallbacks += "android.preference.PreferenceManager$OnActivityStopListener"
    // android.security
    this.androidCallbacks += "android.security.KeyChainAliasCallback"
    // android.speech
    this.androidCallbacks += "android.speech.RecognitionListener"
    // android.speech.tts
    this.androidCallbacks += "android.speech.tts.TextToSpeech$OnInitListener"     
    this.androidCallbacks += "android.speech.tts.TextToSpeech$OnUtteranceCompletedListener"     
    // android.support - omitted
    // android.view
    this.androidCallbacks += "android.view.ActionMode$Callback"
    this.androidCallbacks += "android.view.ActionProvider$VisibilityListener"
    this.androidCallbacks += "android.view.GestureDetector$OnDoubleTapListener"
    this.androidCallbacks += "android.view.GestureDetector$OnGestureListener"
    this.androidCallbacks += "android.view.InputQueue$Callback"
    this.androidCallbacks += "android.view.KeyEvent$Callback"
    this.androidCallbacks += "android.view.MenuItem$OnActionExpandListener"
    this.androidCallbacks += "android.view.MenuItem$OnMenuItemClickListener"
    this.androidCallbacks += "android.view.ScaleGestureDetector$OnScaleGestureListener"
    this.androidCallbacks += "android.view.SurfaceHolder$Callback"
    this.androidCallbacks += "android.view.SurfaceHolder$Callback2"
    this.androidCallbacks += "android.view.TextureView$SurfaceTextureListener"
    this.androidCallbacks += "android.view.View$OnAttachStateChangeListener"
    this.androidCallbacks += "android.view.View$OnClickListener"
    this.androidCallbacks += "android.view.View$OnCreateContextMenuListener"
    this.androidCallbacks += "android.view.View$OnDragListener"
    this.androidCallbacks += "android.view.View$OnFocusChangeListener"
    this.androidCallbacks += "android.view.View$OnGenericMotionListener"
    this.androidCallbacks += "android.view.View$OnHoverListener"
    this.androidCallbacks += "android.view.View$OnKeyListener"
    this.androidCallbacks += "android.view.View$OnLayoutChangeListener"
    this.androidCallbacks += "android.view.View$OnLongClickListener"
    this.androidCallbacks += "android.view.View$OnSystemUiVisibilityChangeListener"
    this.androidCallbacks += "android.view.View$OnTouchListener"
    this.androidCallbacks += "android.view.ViewGroup$OnHierarchyChangeListener"
    this.androidCallbacks += "android.view.ViewStub$OnInflateListener"
    this.androidCallbacks += "android.view.ViewTreeObserver$OnDrawListener"
    this.androidCallbacks += "android.view.ViewTreeObserver$OnGlobalFocusChangeListener"
    this.androidCallbacks += "android.view.ViewTreeObserver$OnGlobalLayoutListener"
    this.androidCallbacks += "android.view.ViewTreeObserver$OnPreDrawListener"
    this.androidCallbacks += "android.view.ViewTreeObserver$OnScrollChangedListener"
    this.androidCallbacks += "android.view.ViewTreeObserver$OnTouchModeChangeListener"
    // android.view.accessibility
    this.androidCallbacks += "android.view.accessibility.AccessibilityManager$AccessibilityStateChangeListener"
    // android.view.animation
    this.androidCallbacks += "android.view.animation.Animation$AnimationListener"
    // android.view.inputmethod
    this.androidCallbacks += "android.view.inputmethod.InputMethod$SessionCallback"
    this.androidCallbacks += "android.view.inputmethod.InputMethodSession$EventCallback"
    // android.view.textservice
    this.androidCallbacks += "android.view.textservice.SpellCheckerSession$SpellCheckerSessionListener"
    // android.webkit.DownloadListener
    this.androidCallbacks += "android.webkit.DownloadListener"
    // android.webkit.WebViewClient
    this.androidCallbacks += "android.webkit.WebViewClient"
      
    // android.widget
    this.androidCallbacks += "android.widget.AbsListView$MultiChoiceModeListener"
    this.androidCallbacks += "android.widget.AbsListView$OnScrollListener"
    this.androidCallbacks += "android.widget.AbsListView$RecyclerListener"
    this.androidCallbacks += "android.widget.AdapterView$OnItemClickListener"
    this.androidCallbacks += "android.widget.AdapterView$OnItemLongClickListener"
    this.androidCallbacks += "android.widget.AdapterView$OnItemSelectedListener"
    this.androidCallbacks += "android.widget.AutoCompleteTextView$OnDismissListener"
    this.androidCallbacks += "android.widget.CalendarView$OnDateChangeListener"
    this.androidCallbacks += "android.widget.Chronometer$OnChronometerTickListener"
    this.androidCallbacks += "android.widget.CompoundButton$OnCheckedChangeListener"
    this.androidCallbacks += "android.widget.DatePicker$OnDateChangedListener"
    this.androidCallbacks += "android.widget.ExpandableListView$OnChildClickListener"
    this.androidCallbacks += "android.widget.ExpandableListView$OnGroupClickListener"
    this.androidCallbacks += "android.widget.ExpandableListView$OnGroupCollapseListener"
    this.androidCallbacks += "android.widget.ExpandableListView$OnGroupExpandListener"
    this.androidCallbacks += "android.widget.Filter$FilterListener"
    this.androidCallbacks += "android.widget.NumberPicker$OnScrollListener"
    this.androidCallbacks += "android.widget.NumberPicker$OnValueChangeListener"
    this.androidCallbacks += "android.widget.PopupMenu$OnDismissListener"
    this.androidCallbacks += "android.widget.PopupMenu$OnMenuItemClickListener"
    this.androidCallbacks += "android.widget.PopupWindow$OnDismissListener"
    this.androidCallbacks += "android.widget.RadioGroup$OnCheckedChangeListener"
    this.androidCallbacks += "android.widget.RatingBar$OnRatingBarChangeListener"
    this.androidCallbacks += "android.widget.SearchView$OnCloseListener"
    this.androidCallbacks += "android.widget.SearchView$OnQueryTextListener"
    this.androidCallbacks += "android.widget.SearchView$OnSuggestionListener"
    this.androidCallbacks += "android.widget.SeekBar$OnSeekBarChangeListener"
    this.androidCallbacks += "android.widget.ShareActionProvider$OnShareTargetSelectedListener"
    this.androidCallbacks += "android.widget.SlidingDrawer$OnDrawerCloseListener"
    this.androidCallbacks += "android.widget.SlidingDrawer$OnDrawerOpenListener"
    this.androidCallbacks += "android.widget.SlidingDrawer$OnDrawerScrollListener"
    this.androidCallbacks += "android.widget.TabHost$OnTabChangeListener"
    this.androidCallbacks += "android.widget.TextView$OnEditorActionListener"
    this.androidCallbacks += "android.widget.TimePicker$OnTimeChangedListener"
    this.androidCallbacks += "android.widget.ZoomButtonsController$OnZoomListener"
    
    // bluetooth
    this.androidCallbacks += "android.bluetooth.BluetoothAdapter$LeScanCallback"
    this.androidCallbacks += "android.bluetooth.BluetoothProfile$ServiceListener"
    
    // nfc
    this.androidCallbacks += "android.nfc.NfcAdapter$CreateNdefMessageCallback"
    this.androidCallbacks += "android.nfc.NfcAdapter$OnNdefPushCompleteCallback" 
  }
}
