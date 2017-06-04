/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.pta.reachingFactsAnalysis.model

import org.argus.amandroid.core.AndroidConstants
import org.argus.jawa.alir.Context
import org.argus.jawa.alir.pta.reachingFactsAnalysis.model.ModelCall
import org.argus.jawa.alir.pta.{FieldSlot, PTAResult, VarSlot}
import org.argus.jawa.alir.pta.reachingFactsAnalysis.{RFAFact, RFAFactFactory}
import org.argus.jawa.core.JawaMethod
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
class ActivityModel extends ModelCall {
  def isModelCall(p: JawaMethod): Boolean = p.getDeclaringClass.getName.equals(AndroidConstants.ACTIVITY)
  
  def doModelCall(s: PTAResult, p: JawaMethod, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact], Boolean) = {
    var newFacts = isetEmpty[RFAFact]
    var delFacts = isetEmpty[RFAFact]
    var byPassFlag = true
    p.getSignature.signature match{
      case "Landroid/app/Activity;.<clinit>:()V" =>  //static constructor
      case "Landroid/app/Activity;.<init>:()V" =>  //public constructor
      case "Landroid/app/Activity;.addContentView:(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V" =>  //public
      case "Landroid/app/Activity;.attach:(Landroid/content/Context;Landroid/app/ActivityThread;Landroid/app/Instrumentation;Landroid/os/IBinder;ILandroid/app/Application;Landroid/content/Intent;Landroid/content/pm/ActivityInfo;Ljava/lang/CharSequence;Landroid/app/Activity;Ljava/lang/String;Landroid/app/Activity$NonConfigurationInstances;Landroid/content/res/Configuration;)V" =>  //final
      case "Landroid/app/Activity;.attach:(Landroid/content/Context;Landroid/app/ActivityThread;Landroid/app/Instrumentation;Landroid/os/IBinder;Landroid/app/Application;Landroid/content/Intent;Landroid/content/pm/ActivityInfo;Ljava/lang/CharSequence;Landroid/app/Activity;Ljava/lang/String;Landroid/app/Activity$NonConfigurationInstances;Landroid/content/res/Configuration;)V" =>  //final
      case "Landroid/app/Activity;.closeContextMenu:()V" =>  //public
      case "Landroid/app/Activity;.closeOptionsMenu:()V" =>  //public
      case "Landroid/app/Activity;.createDialog:(Ljava/lang/Integer;Landroid/os/Bundle;Landroid/os/Bundle;)Landroid/app/Dialog;" =>  //private
      case "Landroid/app/Activity;.createPendingResult:(ILandroid/content/Intent;I)Landroid/app/PendingIntent;" =>  //public
      case "Landroid/app/Activity;.dismissDialog:(I)V" =>  //public final
      case "Landroid/app/Activity;.dispatchActivityResult:(Ljava/lang/String;IILandroid/content/Intent;)V" =>  //
      case "Landroid/app/Activity;.dispatchGenericMotionEvent:(Landroid/view/MotionEvent;)Z" =>  //public
      case "Landroid/app/Activity;.dispatchKeyEvent:(Landroid/view/KeyEvent;)Z" =>  //public
      case "Landroid/app/Activity;.dispatchKeyShortcutEvent:(Landroid/view/KeyEvent;)Z" =>  //public
      case "Landroid/app/Activity;.dispatchPopulateAccessibilityEvent:(Landroid/view/accessibility/AccessibilityEvent;)Z" =>  //public
      case "Landroid/app/Activity;.dispatchTouchEvent:(Landroid/view/MotionEvent;)Z" =>  //public
      case "Landroid/app/Activity;.dispatchTrackballEvent:(Landroid/view/MotionEvent;)Z" =>  //public
      case "Landroid/app/Activity;.dump:(Ljava/lang/String;Ljava/io/FileDescriptor;Ljava/io/PrintWriter;[Ljava/lang/String;)V" =>  //public
      case "Landroid/app/Activity;.dumpInner:(Ljava/lang/String;Ljava/io/FileDescriptor;Ljava/io/PrintWriter;[Ljava/lang/String;)V" =>  //
      case "Landroid/app/Activity;.dumpViewHierarchy:(Ljava/lang/String;Ljava/io/PrintWriter;Landroid/view/View;)V" =>  //private
      case "Landroid/app/Activity;.ensureSearchManager:()V" =>  //private
      case "Landroid/app/Activity;.findViewById:(I)Landroid/view/View;" =>  //public
      case "Landroid/app/Activity;.finish:()V" =>  //public
      case "Landroid/app/Activity;.finishActivity:(I)V" =>  //public
      case "Landroid/app/Activity;.finishActivityFromChild:(Landroid/app/Activity;I)V" =>  //public
      case "Landroid/app/Activity;.finishAffinity:()V" =>  //public
      case "Landroid/app/Activity;.finishFromChild:(Landroid/app/Activity;)V" =>  //public
      case "Landroid/app/Activity;.getActionBar:()Landroid/app/ActionBar;" =>  //public
      case "Landroid/app/Activity;.getActivityToken:()Landroid/os/IBinder;" =>  //public final
      case "Landroid/app/Activity;.getApplication:()Landroid/app/Application;" =>  //public final
      case "Landroid/app/Activity;.getCallingActivity:()Landroid/content/ComponentName;" =>  //public
      case "Landroid/app/Activity;.getCallingPackage:()Ljava/lang/String;" =>  //public
      case "Landroid/app/Activity;.getChangingConfigurations:()I" =>  //public
      case "Landroid/app/Activity;.getComponentName:()Landroid/content/ComponentName;" =>  //public
      case "Landroid/app/Activity;.getCurrentFocus:()Landroid/view/View;" =>  //public
      case "Landroid/app/Activity;.getFragmentManager:()Landroid/app/FragmentManager;" =>  //public
      case "Landroid/app/Activity;.getIntent:()Landroid/content/Intent;" =>  //public
        getIntent(s, args, retVar, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/app/Activity;.getLastNonConfigurationChildInstances:()Ljava/util/HashMap;" =>  //
      case "Landroid/app/Activity;.getLastNonConfigurationInstance:()Ljava/lang/Object;" =>  //public
      case "Landroid/app/Activity;.getLayoutInflater:()Landroid/view/LayoutInflater;" =>  //public
      case "Landroid/app/Activity;.getLoaderManager:()Landroid/app/LoaderManager;" =>  //public
      case "Landroid/app/Activity;.getLoaderManager:(Ljava/lang/String;ZZ)Landroid/app/LoaderManagerImpl;" =>  //
      case "Landroid/app/Activity;.getLocalClassName:()Ljava/lang/String;" =>  //public
      case "Landroid/app/Activity;.getMenuInflater:()Landroid/view/MenuInflater;" =>  //public
      case "Landroid/app/Activity;.getParent:()Landroid/app/Activity;" =>  //public final
      case "Landroid/app/Activity;.getParentActivityIntent:()Landroid/content/Intent;" =>  //public
      case "Landroid/app/Activity;.getPreferences:(I)Landroid/content/SharedPreferences;" =>  //public
      case "Landroid/app/Activity;.getRequestedOrientation:()I" =>  //public
      case "Landroid/app/Activity;.getSystemService:(Ljava/lang/String;)Ljava/lang/Object;" =>  //public
      case "Landroid/app/Activity;.getTaskId:()I" =>  //public
      case "Landroid/app/Activity;.getTitle:()Ljava/lang/CharSequence;" =>  //public final
      case "Landroid/app/Activity;.getTitleColor:()I" =>  //public final
      case "Landroid/app/Activity;.getVolumeControlStream:()I" =>  //public final
      case "Landroid/app/Activity;.getWindow:()Landroid/view/Window;" =>  //public
      case "Landroid/app/Activity;.getWindowManager:()Landroid/view/WindowManager;" =>  //public
      case "Landroid/app/Activity;.hasWindowFocus:()Z" =>  //public
      case "Landroid/app/Activity;.initActionBar:()V" =>  //private
      case "Landroid/app/Activity;.invalidateFragment:(Ljava/lang/String;)V" =>  //
      case "Landroid/app/Activity;.invalidateOptionsMenu:()V" =>  //public
      case "Landroid/app/Activity;.isChangingConfigurations:()Z" =>  //public
      case "Landroid/app/Activity;.isChild:()Z" =>  //public final
      case "Landroid/app/Activity;.isDestroyed:()Z" =>  //public
      case "Landroid/app/Activity;.isFinishing:()Z" =>  //public
      case "Landroid/app/Activity;.isImmersive:()Z" =>  //public
      case "Landroid/app/Activity;.isResumed:()Z" =>  //public final
      case "Landroid/app/Activity;.isTaskRoot:()Z" =>  //public
      case "Landroid/app/Activity;.makeVisible:()V" =>  //
      case "Landroid/app/Activity;.managedQuery:(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;" =>  //public final
      case "Landroid/app/Activity;.managedQuery:(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;" =>  //public final
      case "Landroid/app/Activity;.missingDialog:(I)Ljava/lang/IllegalArgumentException;" =>  //private
      case "Landroid/app/Activity;.moveTaskToBack:(Z)Z" =>  //public
      case "Landroid/app/Activity;.navigateUpTo:(Landroid/content/Intent;)Z" =>  //public
      case "Landroid/app/Activity;.navigateUpToFromChild:(Landroid/app/Activity;Landroid/content/Intent;)Z" =>  //public
      case "Landroid/app/Activity;.onActionModeFinished:(Landroid/view/ActionMode;)V" =>  //public
      case "Landroid/app/Activity;.onActionModeStarted:(Landroid/view/ActionMode;)V" =>  //public
      case "Landroid/app/Activity;.onActivityResult:(IILandroid/content/Intent;)V" =>  //protected
      case "Landroid/app/Activity;.onApplyThemeResource:(Landroid/content/res/Resources$Theme;IZ)V" =>  //protected
      case "Landroid/app/Activity;.onAttachFragment:(Landroid/app/Fragment;)V" =>  //public
      case "Landroid/app/Activity;.onAttachedToWindow:()V" =>  //public
      case "Landroid/app/Activity;.onBackPressed:()V" =>  //public
      case "Landroid/app/Activity;.onChildTitleChanged:(Landroid/app/Activity;Ljava/lang/CharSequence;)V" =>  //protected
      case "Landroid/app/Activity;.onConfigurationChanged:(Landroid/content/res/Configuration;)V" =>  //public
      case "Landroid/app/Activity;.onContentChanged:()V" =>  //public
      case "Landroid/app/Activity;.onContextItemSelected:(Landroid/view/MenuItem;)Z" =>  //public
      case "Landroid/app/Activity;.onContextMenuClosed:(Landroid/view/Menu;)V" =>  //public
      case "Landroid/app/Activity;.onCreate:(Landroid/os/Bundle;)V" =>  //protected
      case "Landroid/app/Activity;.onCreateContextMenu:(Landroid/view/ContextMenu;Landroid/view/View;Landroid/view/ContextMenu$ContextMenuInfo;)V" =>  //public
      case "Landroid/app/Activity;.onCreateDescription:()Ljava/lang/CharSequence;" =>  //public
      case "Landroid/app/Activity;.onCreateDialog:(I)Landroid/app/Dialog;" =>  //protected
      case "Landroid/app/Activity;.onCreateDialog:(ILandroid/os/Bundle;)Landroid/app/Dialog;" =>  //protected
      case "Landroid/app/Activity;.onCreateNavigateUpTaskStack:(Landroid/app/TaskStackBuilder;)V" =>  //public
      case "Landroid/app/Activity;.onCreateOptionsMenu:(Landroid/view/Menu;)Z" =>  //public
      case "Landroid/app/Activity;.onCreatePanelMenu:(ILandroid/view/Menu;)Z" =>  //public
      case "Landroid/app/Activity;.onCreatePanelView:(I)Landroid/view/View;" =>  //public
      case "Landroid/app/Activity;.onCreateThumbnail:(Landroid/graphics/Bitmap;Landroid/graphics/Canvas;)Z" =>  //public
      case "Landroid/app/Activity;.onCreateView:(Landroid/view/View;Ljava/lang/String;Landroid/content/Context;Landroid/util/AttributeSet;)Landroid/view/View;" =>  //public
      case "Landroid/app/Activity;.onCreateView:(Ljava/lang/String;Landroid/content/Context;Landroid/util/AttributeSet;)Landroid/view/View;" =>  //public
      case "Landroid/app/Activity;.onDestroy:()V" =>  //protected
      case "Landroid/app/Activity;.onDetachedFromWindow:()V" =>  //public
      case "Landroid/app/Activity;.onGenericMotionEvent:(Landroid/view/MotionEvent;)Z" =>  //public
      case "Landroid/app/Activity;.onKeyDown:(ILandroid/view/KeyEvent;)Z" =>  //public
      case "Landroid/app/Activity;.onKeyLongPress:(ILandroid/view/KeyEvent;)Z" =>  //public
      case "Landroid/app/Activity;.onKeyMultiple:(IILandroid/view/KeyEvent;)Z" =>  //public
      case "Landroid/app/Activity;.onKeyShortcut:(ILandroid/view/KeyEvent;)Z" =>  //public
      case "Landroid/app/Activity;.onKeyUp:(ILandroid/view/KeyEvent;)Z" =>  //public
      case "Landroid/app/Activity;.onLowMemory:()V" =>  //public
      case "Landroid/app/Activity;.onMenuItemSelected:(ILandroid/view/MenuItem;)Z" =>  //public
      case "Landroid/app/Activity;.onMenuOpened:(ILandroid/view/Menu;)Z" =>  //public
      case "Landroid/app/Activity;.onNavigateUp:()Z" =>  //public
      case "Landroid/app/Activity;.onNavigateUpFromChild:(Landroid/app/Activity;)Z" =>  //public
      case "Landroid/app/Activity;.onNewIntent:(Landroid/content/Intent;)V" =>  //protected
      case "Landroid/app/Activity;.onOptionsItemSelected:(Landroid/view/MenuItem;)Z" =>  //public
      case "Landroid/app/Activity;.onOptionsMenuClosed:(Landroid/view/Menu;)V" =>  //public
      case "Landroid/app/Activity;.onPanelClosed:(ILandroid/view/Menu;)V" =>  //public
      case "Landroid/app/Activity;.onPause:()V" =>  //protected
      case "Landroid/app/Activity;.onPostCreate:(Landroid/os/Bundle;)V" =>  //protected
      case "Landroid/app/Activity;.onPostResume:()V" =>  //protected
      case "Landroid/app/Activity;.onPrepareDialog:(ILandroid/app/Dialog;)V" =>  //protected
      case "Landroid/app/Activity;.onPrepareDialog:(ILandroid/app/Dialog;Landroid/os/Bundle;)V" =>  //protected
      case "Landroid/app/Activity;.onPrepareNavigateUpTaskStack:(Landroid/app/TaskStackBuilder;)V" =>  //public
      case "Landroid/app/Activity;.onPrepareOptionsMenu:(Landroid/view/Menu;)Z" =>  //public
      case "Landroid/app/Activity;.onPreparePanel:(ILandroid/view/View;Landroid/view/Menu;)Z" =>  //public
      case "Landroid/app/Activity;.onRestart:()V" =>  //protected
      case "Landroid/app/Activity;.onRestoreInstanceState:(Landroid/os/Bundle;)V" =>  //protected
      case "Landroid/app/Activity;.onResume:()V" =>  //protected
      case "Landroid/app/Activity;.onRetainNonConfigurationChildInstances:()Ljava/util/HashMap;" =>  //
      case "Landroid/app/Activity;.onRetainNonConfigurationInstance:()Ljava/lang/Object;" =>  //public
      case "Landroid/app/Activity;.onSaveInstanceState:(Landroid/os/Bundle;)V" =>  //protected
      case "Landroid/app/Activity;.onSearchRequested:()Z" =>  //public
      case "Landroid/app/Activity;.onStart:()V" =>  //protected
      case "Landroid/app/Activity;.onStop:()V" =>  //protected
      case "Landroid/app/Activity;.onTitleChanged:(Ljava/lang/CharSequence;I)V" =>  //protected
      case "Landroid/app/Activity;.onTouchEvent:(Landroid/view/MotionEvent;)Z" =>  //public
      case "Landroid/app/Activity;.onTrackballEvent:(Landroid/view/MotionEvent;)Z" =>  //public
      case "Landroid/app/Activity;.onTrimMemory:(I)V" =>  //public
      case "Landroid/app/Activity;.onUserInteraction:()V" =>  //public
      case "Landroid/app/Activity;.onUserLeaveHint:()V" =>  //protected
      case "Landroid/app/Activity;.onWindowAttributesChanged:(Landroid/view/WindowManager$LayoutParams;)V" =>  //public
      case "Landroid/app/Activity;.onWindowFocusChanged:(Z)V" =>  //public
      case "Landroid/app/Activity;.onWindowStartingActionMode:(Landroid/view/ActionMode$Callback;)Landroid/view/ActionMode;" =>  //public
      case "Landroid/app/Activity;.openContextMenu:(Landroid/view/View;)V" =>  //public
      case "Landroid/app/Activity;.openOptionsMenu:()V" =>  //public
      case "Landroid/app/Activity;.overridePendingTransition:(II)V" =>  //public
      case "Landroid/app/Activity;.performCreate:(Landroid/os/Bundle;)V" =>  //final
      case "Landroid/app/Activity;.performDestroy:()V" =>  //final
      case "Landroid/app/Activity;.performPause:()V" =>  //final
      case "Landroid/app/Activity;.performRestart:()V" =>  //final
      case "Landroid/app/Activity;.performRestoreInstanceState:(Landroid/os/Bundle;)V" =>  //final
      case "Landroid/app/Activity;.performResume:()V" =>  //final
      case "Landroid/app/Activity;.performSaveInstanceState:(Landroid/os/Bundle;)V" =>  //final
      case "Landroid/app/Activity;.performStart:()V" =>  //final
      case "Landroid/app/Activity;.performStop:()V" =>  //final
      case "Landroid/app/Activity;.performUserLeaving:()V" =>  //final
      case "Landroid/app/Activity;.recreate:()V" =>  //public
      case "Landroid/app/Activity;.registerForContextMenu:(Landroid/view/View;)V" =>  //public
      case "Landroid/app/Activity;.removeDialog:(I)V" =>  //public final
      case "Landroid/app/Activity;.requestWindowFeature:(I)Z" =>  //public final
      case "Landroid/app/Activity;.restoreManagedDialogs:(Landroid/os/Bundle;)V" =>  //private
      case "Landroid/app/Activity;.retainNonConfigurationInstances:()Landroid/app/Activity$NonConfigurationInstances;" =>  //
      case "Landroid/app/Activity;.runOnUiThread:(Ljava/lang/Runnable;)V" =>  //public final
      case "Landroid/app/Activity;.saveManagedDialogs:(Landroid/os/Bundle;)V" =>  //private
      case "Landroid/app/Activity;.savedDialogArgsKeyFor:(I)Ljava/lang/String;" =>  //private static
      case "Landroid/app/Activity;.savedDialogKeyFor:(I)Ljava/lang/String;" =>  //private static
      case "Landroid/app/Activity;.setContentView:(I)V" =>  //public
      case "Landroid/app/Activity;.setContentView:(Landroid/view/View;)V" =>  //public
      case "Landroid/app/Activity;.setContentView:(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V" =>  //public
      case "Landroid/app/Activity;.setDefaultKeyMode:(I)V" =>  //public final
      case "Landroid/app/Activity;.setFeatureDrawable:(ILandroid/graphics/drawable/Drawable;)V" =>  //public final
      case "Landroid/app/Activity;.setFeatureDrawableAlpha:(II)V" =>  //public final
      case "Landroid/app/Activity;.setFeatureDrawableResource:(II)V" =>  //public final
      case "Landroid/app/Activity;.setFeatureDrawableUri:(ILandroid/net/Uri;)V" =>  //public final
      case "Landroid/app/Activity;.setFinishOnTouchOutside:(Z)V" =>  //public
      case "Landroid/app/Activity;.setImmersive:(Z)V" =>  //public
      case "Landroid/app/Activity;.setIntent:(Landroid/content/Intent;)V" =>  //public
        setIntent(s, args, currentContext) match{case (n, d) => newFacts ++= n; delFacts ++= d}
        byPassFlag = false
      case "Landroid/app/Activity;.setParent:(Landroid/app/Activity;)V" =>  //final
      case "Landroid/app/Activity;.setPersistent:(Z)V" =>  //public
      case "Landroid/app/Activity;.setProgress:(I)V" =>  //public final
      case "Landroid/app/Activity;.setProgressBarIndeterminate:(Z)V" =>  //public final
      case "Landroid/app/Activity;.setProgressBarIndeterminateVisibility:(Z)V" =>  //public final
      case "Landroid/app/Activity;.setProgressBarVisibility:(Z)V" =>  //public final
      case "Landroid/app/Activity;.setRequestedOrientation:(I)V" =>  //public
      case "Landroid/app/Activity;.setResult:(I)V" =>  //public final
      case "Landroid/app/Activity;.setResult:(ILandroid/content/Intent;)V" =>  //public final
      case "Landroid/app/Activity;.setSecondaryProgress:(I)V" =>  //public final
      case "Landroid/app/Activity;.setTitle:(I)V" =>  //public
      case "Landroid/app/Activity;.setTitle:(Ljava/lang/CharSequence;)V" =>  //public
      case "Landroid/app/Activity;.setTitleColor:(I)V" =>  //public
      case "Landroid/app/Activity;.setVisible:(Z)V" =>  //public
      case "Landroid/app/Activity;.setVolumeControlStream:(I)V" =>  //public final
      case "Landroid/app/Activity;.shouldUpRecreateTask:(Landroid/content/Intent;)Z" =>  //public
      case "Landroid/app/Activity;.showDialog:(I)V" =>  //public final
      case "Landroid/app/Activity;.showDialog:(ILandroid/os/Bundle;)Z" =>  //public final
      case "Landroid/app/Activity;.startActionMode:(Landroid/view/ActionMode$Callback;)Landroid/view/ActionMode;" =>  //public
      case "Landroid/app/Activity;.startActivities:([Landroid/content/Intent;)V" =>  //public
      case "Landroid/app/Activity;.startActivities:([Landroid/content/Intent;Landroid/os/Bundle;)V" =>  //public
      case "Landroid/app/Activity;.startActivity:(Landroid/content/Intent;)V" =>  //public
      case "Landroid/app/Activity;.startActivity:(Landroid/content/Intent;Landroid/os/Bundle;)V" =>  //public
      case "Landroid/app/Activity;.startActivityAsUser:(Landroid/content/Intent;Landroid/os/Bundle;Landroid/os/UserHandle;)V" =>  //public
      case "Landroid/app/Activity;.startActivityAsUser:(Landroid/content/Intent;Landroid/os/UserHandle;)V" =>  //public
      case "Landroid/app/Activity;.startActivityForResult:(Landroid/content/Intent;I)V" =>  //public
      case "Landroid/app/Activity;.startActivityForResult:(Landroid/content/Intent;ILandroid/os/Bundle;)V" =>  //public
      case "Landroid/app/Activity;.startActivityFromChild:(Landroid/app/Activity;Landroid/content/Intent;I)V" =>  //public
      case "Landroid/app/Activity;.startActivityFromChild:(Landroid/app/Activity;Landroid/content/Intent;ILandroid/os/Bundle;)V" =>  //public
      case "Landroid/app/Activity;.startActivityFromFragment:(Landroid/app/Fragment;Landroid/content/Intent;I)V" =>  //public
      case "Landroid/app/Activity;.startActivityFromFragment:(Landroid/app/Fragment;Landroid/content/Intent;ILandroid/os/Bundle;)V" =>  //public
      case "Landroid/app/Activity;.startActivityIfNeeded:(Landroid/content/Intent;I)Z" =>  //public
      case "Landroid/app/Activity;.startActivityIfNeeded:(Landroid/content/Intent;ILandroid/os/Bundle;)Z" =>  //public
      case "Landroid/app/Activity;.startIntentSender:(Landroid/content/IntentSender;Landroid/content/Intent;III)V" =>  //public
      case "Landroid/app/Activity;.startIntentSender:(Landroid/content/IntentSender;Landroid/content/Intent;IIILandroid/os/Bundle;)V" =>  //public
      case "Landroid/app/Activity;.startIntentSenderForResult:(Landroid/content/IntentSender;ILandroid/content/Intent;III)V" =>  //public
      case "Landroid/app/Activity;.startIntentSenderForResult:(Landroid/content/IntentSender;ILandroid/content/Intent;IIILandroid/os/Bundle;)V" =>  //public
      case "Landroid/app/Activity;.startIntentSenderForResultInner:(Landroid/content/IntentSender;ILandroid/content/Intent;IILandroid/app/Activity;Landroid/os/Bundle;)V" =>  //private
      case "Landroid/app/Activity;.startIntentSenderFromChild:(Landroid/app/Activity;Landroid/content/IntentSender;ILandroid/content/Intent;III)V" =>  //public
      case "Landroid/app/Activity;.startIntentSenderFromChild:(Landroid/app/Activity;Landroid/content/IntentSender;ILandroid/content/Intent;IIILandroid/os/Bundle;)V" =>  //public
      case "Landroid/app/Activity;.startManagingCursor:(Landroid/database/Cursor;)V" =>  //public
      case "Landroid/app/Activity;.startNextMatchingActivity:(Landroid/content/Intent;)Z" =>  //public
      case "Landroid/app/Activity;.startNextMatchingActivity:(Landroid/content/Intent;Landroid/os/Bundle;)Z" =>  //public
      case "Landroid/app/Activity;.startSearch:(Ljava/lang/String;ZLandroid/os/Bundle;Z)V" =>  //public
      case "Landroid/app/Activity;.stopManagingCursor:(Landroid/database/Cursor;)V" =>  //public
      case "Landroid/app/Activity;.takeKeyEvents:(Z)V" =>  //public
      case "Landroid/app/Activity;.triggerSearch:(Ljava/lang/String;Landroid/os/Bundle;)V" =>  //public
      case "Landroid/app/Activity;.unregisterForContextMenu:(Landroid/view/View;)V" =>  //public
      case _ =>
    }
    (newFacts, delFacts, byPassFlag)
  }
  
  private def setIntent(s: PTAResult, args: List[String], currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.size >1)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    val intentSlot = VarSlot(args(1), isBase = false, isArg = true)
    val intentValue = s.pointsToSet(intentSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    var delfacts = isetEmpty[RFAFact]
    thisValue.foreach{
      tv =>
        val mIntentSlot = FieldSlot(tv, AndroidConstants.ACTIVITY_INTENT)
        if(thisValue.size == 1){
          for (v <- s.pointsToSet(mIntentSlot, currentContext)) {
            delfacts += new RFAFact(mIntentSlot, v)
          }
        }
        newfacts ++= intentValue.map(iv => new RFAFact(mIntentSlot, iv))
    }
    (newfacts, delfacts)
  }
  
  private def getIntent(s: PTAResult, args: List[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    require(args.nonEmpty)
    val thisSlot = VarSlot(args.head, isBase = false, isArg = true)
    val thisValue = s.pointsToSet(thisSlot, currentContext)
    var newfacts = isetEmpty[RFAFact]
    val delfacts = isetEmpty[RFAFact]
    thisValue.foreach{ tv =>
      val mIntentSlot = FieldSlot(tv, AndroidConstants.ACTIVITY_INTENT)
      val mIntentValue = s.pointsToSet(mIntentSlot, currentContext)
//        val mUnknownIntentSlot = FieldSlot(tv, "ALL")
//        s.pointsToSet(mUnknownIntentSlot, currentContext) foreach {
//          ins =>
//            mIntentValue += UnknownInstance(new NormalType(AndroidConstants.INTENT), ins.defSite)
//        }
//        tv.getFieldsUnknownDefSites.foreach{
//          case (defsite, fields) =>
//            if(fields.contains("ALL")) mIntentValue += UnknownInstance(new NormalType(AndroidConstants.INTENT), defsite)
//            if(fields.contains(AndroidConstants.ACTIVITY_INTENT)) mIntentValue += UnknownInstance(new NormalType(AndroidConstants.INTENT), defsite)
//        }
      newfacts ++= mIntentValue.map(miv=> new RFAFact(VarSlot(retVar, isBase = false, isArg = false), miv))
    }
    (newfacts, delfacts)
  }
  
}
