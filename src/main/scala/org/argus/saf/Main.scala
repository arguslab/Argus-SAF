/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.saf

import org.apache.commons.cli._
import org.argus.amandroid.core.AndroidGlobalConfig
import org.argus.amandroid.core.decompile.DecompileLevel
import org.argus.amandroid.plugin.{ApiMisuseModules, TaintAnalysisApproach, TaintAnalysisModules}
import org.argus.jnsaf.server.JNSafServer
import org.argus.jnsaf.submitter.{ApkSubmitter, BenchmarkSubmitter}
import org.argus.saf.cli._

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
object Main extends App {

  private val version = org.argus.BuildInfo.version

  private val generalOptionGroup: OptionGroup = new OptionGroup
  private val normalOptions: Options = new Options
  private val decompilerOptions: Options = new Options
  private val taintOptions: Options = new Options
  private val apiMisuseOptions: Options = new Options
  private val apkSubmitterOptions: Options = new Options
  private val allOptions: Options = new Options

  private def createOptions(): Unit = {
    // create options
    val versionOption: Option = Option.builder().longOpt("version").desc("Prints the version then exits.").build()

    val debugDecOption: Option = Option.builder("d").longOpt("debug").desc("Output debug information.").build()
    val guessPackageOption: Option = Option.builder("g").longOpt("guess").desc("Guess application package prefixes.").build()
    val approachOption: Option = Option.builder("a").longOpt("approach").desc("Choose analysis approach. [Default: BOTTOM_UP, Choices: (BOTTOM_UP, COMPONENT_BASED)]").hasArg(true).argName("approach").build()
    val outputOption: Option = Option.builder("o").longOpt("output").desc("Set output directory. [Default: .]").hasArg(true).argName("dir").build()
    val forceDeleteOption: Option = Option.builder("f").longOpt("force").desc("Force delete previous decompile result. [Default: false]").build()
    val srclevelOption: Option = Option.builder("sl").longOpt("src-level").desc("Application code decompile level. [Default: UNTYPED, Choices: (NO, SIGNATURE, UNTYPED, TYPED)]").hasArg(true).argName("level").build()
    val liblevelOption: Option = Option.builder("ll").longOpt("lib-level").desc("Third party library decompile level. [Default: SIGNATURE, Choices: (NO, SIGNATURE, UNTYPED, TYPED)]").hasArg(true).argName("level").build()
    val iniPathOption: Option = Option.builder("i").longOpt("ini").desc("Set .ini configuration file path.").hasArg(true).argName("path").build()

    val taintmoduleOption: Option = Option.builder("mo")
      .longOpt("module").desc("Taint analysis module to use. [Default: DATA_LEAKAGE, Choices: (COMMUNICATION_LEAKAGE, OAUTH_TOKEN_TRACKING, PASSWORD_TRACKING, INTENT_INJECTION, DATA_LEAKAGE)]")
      .hasArg(true).argName("name").build()

    val apimoduleOption: Option = Option.builder("c")
      .longOpt("checker").desc("Api checker to use. [Default: HIDE_ICON, Choices: (CRYPTO_MISUSE, HIDE_ICON, SSLTLS_MISUSE)]")
      .hasArg(true).argName("name").build()

    generalOptionGroup.addOption(debugDecOption)
    generalOptionGroup.addOption(guessPackageOption)
    generalOptionGroup.addOption(outputOption)
    generalOptionGroup.addOption(iniPathOption)
    generalOptionGroup.addOption(forceDeleteOption)

    normalOptions.addOption(versionOption)

    decompilerOptions.addOptionGroup(generalOptionGroup)
    decompilerOptions.addOption(srclevelOption)
    decompilerOptions.addOption(liblevelOption)

    taintOptions.addOptionGroup(generalOptionGroup)
    taintOptions.addOption(taintmoduleOption)
    taintOptions.addOption(approachOption)

    apiMisuseOptions.addOptionGroup(generalOptionGroup)
    apiMisuseOptions.addOption(apimoduleOption)

    apkSubmitterOptions.addOption(approachOption)

    allOptions.addOption(versionOption)
    allOptions.addOption(guessPackageOption)
    allOptions.addOption(approachOption)
    allOptions.addOption(debugDecOption)
    allOptions.addOption(outputOption)
    allOptions.addOption(forceDeleteOption)
    allOptions.addOption(srclevelOption)
    allOptions.addOption(liblevelOption)
    allOptions.addOption(iniPathOption)
    allOptions.addOption(taintmoduleOption)
    allOptions.addOption(apimoduleOption)

  }

  object Mode extends Enumeration {
    val ARGUS_SAF, APICHECK, DECOMPILE, TAINT, JNSAF_SERVER, APK_SUBMITTER, BENCHMARK_SUBMITTER = Value
  }

  private def usage(mode: Mode.Value): Unit ={
    val formatter: HelpFormatter = new HelpFormatter
    formatter.setWidth(120)
    mode match {
      case Mode.ARGUS_SAF =>
        println(s"""Argus-SAF v$version - a static analysis framework for Android apks
                    |Copyright 2018 Argus Cybersecurity Laboratory, University of South Florida""".stripMargin)
        println("")
        println("""Available Modes:
                  |  a[picheck]    Detecting API misuse.
                  |  d[ecompile]   Decompile Apk file(s).
                  |  t[aint]       Perform taint analysis on Apk(s).
                  |  jn[saf]       Launch JN-SAF server.
                  |  s[ubmitter]   Apk submitter.
                  |  benchmark     Run Benchmark.""".stripMargin)
        println("")
        formatter.printHelp("<options>", normalOptions)
        println("For additional info, see: http://pag.arguslab.org/argus-saf")
      case Mode.APICHECK =>
        formatter.printHelp("a[picheck] [options] <file_apk/dir>", apiMisuseOptions)
      case Mode.DECOMPILE =>
        formatter.printHelp("d[compile] [options] <file_apk/dir>", decompilerOptions)
      case Mode.TAINT =>
        formatter.printHelp("t[aint] [options] <file_apk/dir>", taintOptions)
      case Mode.JNSAF_SERVER =>
        println("jn[saf] <out_dir> <jnsaf_port> <nativedroid_address> <nativedroid_port>")
      case Mode.APK_SUBMITTER =>
        println("s[ubmitter] [options] <file_apk/dir> <address> <port>", apkSubmitterOptions)
      case Mode.BENCHMARK_SUBMITTER =>
        println("benchmark [options] <file_dir> <address> <port> <expected_result_file>", apkSubmitterOptions)
    }

  }

  // create the command line parser
  val parser: CommandLineParser = new DefaultParser()
  var commandLine: CommandLine = _

  createOptions()

  try {
    // parse the command line arguments
    commandLine = parser.parse(allOptions, args)
  }
  catch {
    case exp: ParseException =>
      println("ParseException:" + exp.getMessage)
      exp.printStackTrace()
      usage(Mode.ARGUS_SAF)
      System.exit(1)
  }

  var cmdFound: Boolean = false

  try {
    if(commandLine.hasOption("i") || commandLine.hasOption("ini")) {
      AndroidGlobalConfig.iniPathOpt = Some(commandLine.getOptionValue("i"))
    }
    for (opt <- commandLine.getArgs) {
      if (opt.equalsIgnoreCase("d") || opt.equalsIgnoreCase("decompile")) {
        cmdDecompile(commandLine)
        cmdFound = true
      }
      else if (opt.equalsIgnoreCase("t") || opt.equalsIgnoreCase("taint")) {
        cmdTaintAnalysis(commandLine)
        cmdFound = true
      }
      else if (opt.equalsIgnoreCase("a") || opt.equalsIgnoreCase("apicheck")) {
        cmdApiMisuse(commandLine)
        cmdFound = true
      }
      else if (opt.equalsIgnoreCase("jn") || opt.equalsIgnoreCase("jnsaf")) {
        cmdStartJNSafServer(commandLine)
        cmdFound = true
      }
      else if (opt.equalsIgnoreCase("s") || opt.equalsIgnoreCase("submitter")) {
        cmdApkSubmitter(commandLine)
        cmdFound = true
      }
      else if (opt.equalsIgnoreCase("benchmark")) {
        cmdBenchmarkSubmitter(commandLine)
        cmdFound = true
      }
    }
  } catch {
    case exp: Exception =>
      println("Unexpected exception:" + exp.getMessage)
      exp.printStackTrace()
  } finally {
    // if no commands ran, run the version / usage check.
    if (!cmdFound) {
      if (commandLine.hasOption("-v") || commandLine.hasOption("--version")) {
        println("Argus-SAF v" + version)
      }
      else {
        usage(Mode.ARGUS_SAF)
      }
    }
  }

  case class ArgNotEnoughException(msg: String) extends Exception(msg)

  private def cmdDecompile(cli: CommandLine): Unit = {
    var debug = false
    var outputPath: String = "."
    var forceDelete: Boolean = false
    var srcLevel: DecompileLevel.Value = DecompileLevel.UNTYPED
    var libLevel: DecompileLevel.Value = DecompileLevel.SIGNATURE
    if(cli.hasOption("d") || cli.hasOption("debug")) {
      debug = true
    }
    if(cli.hasOption("o") || cli.hasOption("output")) {
      outputPath = cli.getOptionValue("o")
    }
    if(cli.hasOption("f") || cli.hasOption("force")) {
      forceDelete = true
    }
    if(cli.hasOption("sl") || cli.hasOption("src-level")) {
      srcLevel = cli.getOptionValue("sl") match {
        case "NO" => DecompileLevel.NO
        case "SIGNATURE" => DecompileLevel.SIGNATURE
        case "UNTYPED" => DecompileLevel.UNTYPED
        case "TYPED" => DecompileLevel.TYPED
      }
    }
    if(cli.hasOption("ll") || cli.hasOption("lib-level")) {
      libLevel = cli.getOptionValue("sl") match {
        case "NO" => DecompileLevel.NO
        case "SIGNATURE" => DecompileLevel.SIGNATURE
        case "UNTYPED" => DecompileLevel.UNTYPED
        case "TYPED" => DecompileLevel.TYPED
      }
    }
    var sourcePath: String = null

    try {
      sourcePath = cli.getArgList.get(1)
    } catch {
      case _: Exception =>
        usage(Mode.DECOMPILE)
        System.exit(0)
    }
    Decompiler(debug, sourcePath, outputPath, forceDelete, srcLevel, libLevel)
  }

  private def cmdTaintAnalysis(cli: CommandLine): Unit = {
    var debug = false
    var guessPackage = false
    var outputPath: String = "."
    var forceDelete: Boolean = false
    var module: TaintAnalysisModules.Value = TaintAnalysisModules.DATA_LEAKAGE
    var approach: TaintAnalysisApproach.Value = TaintAnalysisApproach.BOTTOM_UP
    if(cli.hasOption("d") || cli.hasOption("debug")) {
      debug = true
    }
    if(cli.hasOption("g") || cli.hasOption("guess")) {
      guessPackage = true
    }
    if(cli.hasOption("o") || cli.hasOption("output")) {
      outputPath = cli.getOptionValue("o")
    }
    if(cli.hasOption("f") || cli.hasOption("force")) {
      forceDelete = true
    }
    if(cli.hasOption("mo") || cli.hasOption("module")) {
      module = cli.getOptionValue("mo") match {
        case "DATA_LEAKAGE" => TaintAnalysisModules.DATA_LEAKAGE
        case "INTENT_INJECTION" => TaintAnalysisModules.INTENT_INJECTION
        case "PASSWORD_TRACKING" => TaintAnalysisModules.PASSWORD_TRACKING
        case "OAUTH_TOKEN_TRACKING" => TaintAnalysisModules.OAUTH_TOKEN_TRACKING
        case "COMMUNICATION_LEAKAGE" => TaintAnalysisModules.COMMUNICATION_LEAKAGE
      }
    }
    if(cli.hasOption("a") || cli.hasOption("approach")) {
      approach = cli.getOptionValue("a") match {
        case "BOTTOM_UP" => TaintAnalysisApproach.BOTTOM_UP
        case "COMPONENT_BASED" => TaintAnalysisApproach.COMPONENT_BASED
      }
    }
    var sourcePath: String = null

    try {
      sourcePath = cli.getArgList.get(1)
    } catch {
      case _: Exception =>
        usage(Mode.TAINT)
        System.exit(0)
    }
    TaintAnalysis(module, debug, sourcePath, outputPath, forceDelete, guessPackage, approach)
  }

  private def cmdApiMisuse(cli: CommandLine): Unit = {
    var debug = false
    var guessPackage = false
    var outputPath: String = "."
    var forceDelete: Boolean = false
    var module: ApiMisuseModules.Value = ApiMisuseModules.CRYPTO_MISUSE
    if(cli.hasOption("d") || cli.hasOption("debug")) {
      debug = true
    }
    if(cli.hasOption("g") || cli.hasOption("guess")) {
      guessPackage = true
    }
    if(cli.hasOption("o") || cli.hasOption("output")) {
      outputPath = cli.getOptionValue("o")
    }
    if(cli.hasOption("f") || cli.hasOption("force")) {
      forceDelete = true
    }
    if(cli.hasOption("c") || cli.hasOption("checker")) {
      module = cli.getOptionValue("c") match {
        case "CRYPTO_MISUSE" => ApiMisuseModules.CRYPTO_MISUSE
        case "HIDE_ICON" => ApiMisuseModules.HIDE_ICON
        case "SSLTLS_MISUSE" => ApiMisuseModules.SSLTLS_MISUSE
      }
    }
    var sourcePath: String = null

    try {
      sourcePath = cli.getArgList.get(1)
    } catch {
      case _: Exception =>
        usage(Mode.APICHECK)
        System.exit(0)
    }
    ApiMisuse(module, debug, sourcePath, outputPath, forceDelete, guessPackage)
  }

  private def cmdStartJNSafServer(cli: CommandLine): Unit = {
    var outputPath: String = null
    var port: Int = 0
    var nativedroid_address: String = null
    var nativedroid_port: Int = 0
    try {
      outputPath = cli.getArgList.get(1)
      port = cli.getArgList.get(2).toInt
      nativedroid_address = cli.getArgList.get(3)
      nativedroid_port = cli.getArgList.get(4).toInt
    } catch {
      case _: Exception =>
        usage(Mode.JNSAF_SERVER)
        System.exit(0)
    }
    JNSafServer(outputPath, port, nativedroid_address, nativedroid_port)
  }

  private def cmdApkSubmitter(cli: CommandLine): Unit = {
    var outputPath: String = null
    var address: String = null
    var port: Int = 0
    var approach: TaintAnalysisApproach.Value = TaintAnalysisApproach.BOTTOM_UP
    if(cli.hasOption("a") || cli.hasOption("approach")) {
      approach = cli.getOptionValue("a") match {
        case "BOTTOM_UP" => TaintAnalysisApproach.BOTTOM_UP
        case "COMPONENT_BASED" => TaintAnalysisApproach.COMPONENT_BASED
      }
    }
    try {
      outputPath = cli.getArgList.get(1)
      address = cli.getArgList.get(2)
      port = cli.getArgList.get(3).toInt
    } catch {
      case _: Exception =>
        usage(Mode.APK_SUBMITTER)
        System.exit(0)
    }
    ApkSubmitter(outputPath, address, port, approach)
  }

  private def cmdBenchmarkSubmitter(cli: CommandLine): Unit = {
    var outputPath: String = null
    var address: String = null
    var port: Int = 0
    var expectedFile: String = null
    var approach: TaintAnalysisApproach.Value = TaintAnalysisApproach.BOTTOM_UP
    if(cli.hasOption("a") || cli.hasOption("approach")) {
      approach = cli.getOptionValue("a") match {
        case "BOTTOM_UP" => TaintAnalysisApproach.BOTTOM_UP
        case "COMPONENT_BASED" => TaintAnalysisApproach.COMPONENT_BASED
      }
    }
    try {
      outputPath = cli.getArgList.get(1)
      address = cli.getArgList.get(2)
      port = cli.getArgList.get(3).toInt
      expectedFile = cli.getArgList.get(4)
    } catch {
      case _: Exception =>
        usage(Mode.BENCHMARK_SUBMITTER)
        System.exit(0)
    }
    BenchmarkSubmitter(outputPath, address, port, expectedFile, approach)
  }
}
