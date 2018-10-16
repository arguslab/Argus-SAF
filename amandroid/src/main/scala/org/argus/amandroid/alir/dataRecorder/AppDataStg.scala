/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.dataRecorder

/**
  * Created by fgwei on 8/10/16.
  */
object AppDataStg {
  def getStg: String =
    """
      |group AppData;
      |
      |delimiters "$", "$"
      |
      |AppData(name, uses_permissions, components, dynamicRegisteredComponents, taintResult) ::= <<
      |Application Name: $name$
      |Uses Permissions: $uses_permissions ; separator=", "$
      |
      |$components ; separator="\n\n"$
      |
      |$if(dynamicRegisteredComponents)$Dynamic Registered Components:
      |$dynamicRegisteredComponents ; separator="\n\n"$$endif$
      |
      |
      |Taint analysis result:
      |  $taintResult$
      |>>
      |
      |ComponentData(compName, typ, exported, dynamicReg, protectPermission, intentFilters, iccInfos) ::= <<
      |Component $compName$
      |  Component type: $typ$
      |  Exported: $exported$
      |  Dynamic Registered: $dynamicReg$
      |  Required Permission: $protectPermission ; separator=", "$
      |  IntentFilters:
      |    $intentFilters ; separator="\n"$
      |
      |  Inter-component communication (ICC) Result:
      |    $iccInfos ; separator="\n"$
      |>>
      |
      |DynamicRegisteredComponentData(compName, typ, protectPermission, intentFilters) ::= <<
      |Dynamic registered component: $compName$
      |  typ: $typ$
      |  Protect Permission: $protectPermission$
      |  IntentFilters:
      |    $intentFilters ; separator="\n"$
      |>>
      |
      |IntentFilter(actions, categories, data) ::= <<
      |IntentFilter:($if(actions)$Actions:["$actions ; separator="\",\""$"]$endif$$if(categories)$,Categories:["$categories ; separator="\",\""$"]$endif$$if(data)$,Data:[$data$]$endif$)
      |>>
      |
      |Data(schemes, hosts, ports, paths, pathPrefixs, pathPatterns, mimeTypes) ::= <<
      |($if(schemes)$Schemes:<"$schemes ; separator="\",\""$">,$endif$$if(hosts)$Hosts:<"$hosts ; separator="\",\""$">,$endif$$if(ports)$Ports:<"$ports ; separator="\",\""$">,$endif$$if(paths)$Paths:<"$paths ; separator="\",\""$">,$endif$$if(pathPrefixs)$PathPrefixs:<"$pathPrefixs ; separator="\",\""$">,$endif$$if(pathPatterns)$PathPatterns:<"$pathPatterns ; separator="\",\""$">,$endif$$if(mimeTypes)$MimeTypes:<"$mimeTypes ; separator="\",\""$">$endif$)
      |>>
      |
      |IccInfo(procs, context, intents) ::= <<
      |ICC call details are listed below:
      |  Caller Procedure: $procs ; separator="\n"$
      |  Caller Context: $context$
      |  Outgoing Intents via this call:
      |    $intents ; separator="\n"$
      |>>
      |
      |Intent(componentNames, actions, categories, datas, typs, targets) ::= <<
      |Intent:
      |  $if(componentNames)$mComponentNames:
      |  "$componentNames ; separator="\"\n  \""$"$endif$
      |
      |  $if(actions)$mActions:
      |  "$actions ; separator="\"\n  \""$"$endif$
      |
      |  $if(categories)$mCategories:
      |  "$categories ; separator="\"\n  \""$"$endif$
      |
      |  $if(datas)$mDatas:
      |  $datas ; separator="\"\n  \""$$endif$
      |
      |  $if(typs)$mimeTypes:
      |  "$typs ; separator="\"\n  \""$"$endif$
      |
      |  ICC destinations:
      |    $targets ; separator="\n"$
      |>>
      |
      |UriData(scheme, host, port, path, pathPrefix, pathPattern) ::= <<
      |<Scheme:"$scheme$",Host:"$host$",Port:"$port$",Path:"$path$",PathPrefix:"$pathPrefix$",PathPattern:"$pathPattern$">
      |>>
      |
      |TaintResult(sources, sinks, paths) ::= <<
      |Sources found:
      |  $sources ; separator="\n"$
      |Sinks found:
      |  $sinks ; separator="\n"$
      |Discovered taint paths are listed below:
      |  $paths ; separator="\n\n"$
      |>>
      |
      |Target(proc, typ) ::= <<
      |Target Component: $proc$, Intent Type: $typ$
      |>>
      |
      |SourceSinkInfo(descriptors) ::= <<
      |<Descriptors: $descriptors ; separator=" "$>
      |>>
      |
      |TaintPath(source, sink, typs, path) ::= <<
      |TaintPath:
      |  Source: $source$
      |  Sink: $sink$
      |  Types: $typs ; separator=", "$
      |  The path consists of the following edges ("->"). The nodes have the context information (p1 to pn means which parameter). The source is at the top :
      |    $path ; separator="\n"$
      |>>
    """.stripMargin
}
