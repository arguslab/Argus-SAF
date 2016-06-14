/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.saf

import org.apache.commons.cli._
import org.argus.amandroid.cli.{ApiMisuse, Decompiler, Staging, TaintAnalysis}
import org.argus.amandroid.plugin.{ApiMisuseModules, TaintAnalysisModules}

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
object Main extends App {

  private val version = org.argus.BuildInfo.version


  object Verbosity extends Enumeration {
    val VERBOSE, NORMAL, QUIET = Value
  }
  // set verbosity default
//  private var verbosity = Verbosity.NORMAL
  private val generalOptionGroup: OptionGroup = new OptionGroup
  private val normalOptions: Options = new Options
  private val decompilerOptions: Options = new Options
  private val taintOptions: Options = new Options
  private val apiMisuseOptions: Options = new Options
  private val stageOptions: Options = new Options
  private val allOptions: Options = new Options

  private def createOptions(): Unit = {
    // create options
    val versionOption: Option = Option.builder().longOpt("version").desc("Prints the version then exits.").build()

//    val verboseOption: Option = Option.builder("v").longOpt("verbose").desc("Execute in verbose mode.").build()
//
//    val quietOption: Option = Option.builder("q").longOpt("quiet").desc("Execute in quite mode.").build()

    val debugDecOption: Option = Option.builder("d").longOpt("debug").desc("Output debug information.").build()
    val outputOption: Option = Option.builder("o")
      .longOpt("output").desc("Set output directory. [Default: .]")
      .hasArg(true).argName("dir").build()
    val iniPathOption: Option = Option.builder("i")
      .longOpt("ini").desc("Set .ini configuration file path.")
      .hasArg(true).argName("path").build()

    val taintmoduleOption: Option = Option.builder("mo")
      .longOpt("module").desc("Taint analysis module to use. [Default: DATA_LEAKAGE, Choices: (COMMUNICATION_LEAKAGE, OAUTH_TOKEN_TRACKING, PASSWORD_TRACKING, INTENT_INJECTION, DATA_LEAKAGE)]")
      .hasArg(true).argName("name").build()

    val apimoduleOption: Option = Option.builder("c")
      .longOpt("checker").desc("Api checker to use. [Default: HIDE_ICON, Choices: (CRYPTO_MISUSE, HIDE_ICON)]")
      .hasArg(true).argName("name").build()

//    generalOptionGroup.addOption(verboseOption)
//    generalOptionGroup.addOption(quietOption)
    generalOptionGroup.addOption(debugDecOption)
    generalOptionGroup.addOption(outputOption)
    generalOptionGroup.addOption(iniPathOption)

    normalOptions.addOption(versionOption)

    decompilerOptions.addOptionGroup(generalOptionGroup)

    taintOptions.addOptionGroup(generalOptionGroup)
    taintOptions.addOption(taintmoduleOption)

    apiMisuseOptions.addOptionGroup(generalOptionGroup)
    apiMisuseOptions.addOption(apimoduleOption)

    stageOptions.addOptionGroup(generalOptionGroup)

    allOptions.addOption(versionOption)
    allOptions.addOption(debugDecOption)
    allOptions.addOption(outputOption)
    allOptions.addOption(taintmoduleOption)
    allOptions.addOption(apimoduleOption)
  }

  object Mode extends Enumeration {
    val AMANDROID, APICHECK, DECOMPILE, STAGE, TAINT = Value
  }

  private def usage(mode: Mode.Value): Unit ={
    val formatter: HelpFormatter = new HelpFormatter
    formatter.setWidth(120)
    mode match {
      case Mode.AMANDROID =>
        println(s"""Amandroid v$version - a static analysis framework for Android apks
                    |Copyright 2016 Argus Laboratory, University of South Florida""".stripMargin)
        println("")
        println("""Available Modes:
                  |  a[picheck]    Detecting API misuse.
                  |  d[ecompile]   Decompile Apk file(s).
                  |  s[tage]       Stage Amandroid middle results.
                  |  t[aint]       Perform taint analysis on Apk(s).""".stripMargin)
        println("")
        formatter.printHelp("<options>", normalOptions)
        println("For additional info, see: http://amandroid.sireum.org/")
      case Mode.APICHECK =>
        formatter.printHelp("a[picheck] [options] <file_apk/dir>", apiMisuseOptions)
      case Mode.DECOMPILE =>
        formatter.printHelp("d[compile] [options] <file_apk/dir>", decompilerOptions)
      case Mode.STAGE =>
        formatter.printHelp("s[tage] [options] <file_apk/dir>", stageOptions)
      case Mode.TAINT =>
        formatter.printHelp("t[aint] [options] <file_apk/dir>", taintOptions)
    }

  }

  // create the command line parser
  val parser: CommandLineParser = new DefaultParser()
  var commandLine: CommandLine = null

  createOptions()

  try {
    // parse the command line arguments
    commandLine = parser.parse(allOptions, args)
  }
  catch {
    case exp: ParseException =>
      println("ParseException:" + exp.getMessage)
      usage(Mode.AMANDROID)
      System.exit(1)
  }

//  setupLogging(verbosity)

  var cmdFound: Boolean = false

  try {
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
      else if (opt.equalsIgnoreCase("s") || opt.equalsIgnoreCase("stage")) {
        cmdStaging(commandLine)
        cmdFound = true
      }
    }
  } catch {
    case exp: Exception =>
      println("Unexpected exception:" + exp.getMessage)
  } finally {
    // if no commands ran, run the version / usage check.
    if (!cmdFound) {
      if (commandLine.hasOption("-v") || commandLine.hasOption("--version")) {
        println("Amandroid v" + version)
      }
      else {
        usage(Mode.AMANDROID)
      }
    }
  }

  case class ArgNotEnoughException(msg: String) extends Exception(msg)

  private def cmdDecompile(cli: CommandLine) = {
    var debug = false
    var outputPath: String = "."
    // check for verbose / quiet
//    if (commandLine.hasOption("v") || commandLine.hasOption("verbose")) {
//      verbosity = Verbosity.VERBOSE
//    }
//    else if (commandLine.hasOption("q") || commandLine.hasOption("quiet")) {
//      verbosity = Verbosity.QUIET
//    }
    if(cli.hasOption("d") || cli.hasOption("debug")) {
      debug = true
    }
    if(cli.hasOption("o") || cli.hasOption("output")) {
      outputPath = cli.getOptionValue("o")
    }
    var sourcePath: String = null

    try {
      sourcePath = cli.getArgList.get(1)
    } catch {
      case e: Exception =>
        usage(Mode.DECOMPILE)
        System.exit(0)
    }
    Decompiler(debug, sourcePath, outputPath)
  }

  private def cmdTaintAnalysis(cli: CommandLine) = {
    var debug = false
    var outputPath: String = "."
    var module: TaintAnalysisModules.Value = TaintAnalysisModules.DATA_LEAKAGE
    if(cli.hasOption("d") || cli.hasOption("debug")) {
      debug = true
    }
    if(cli.hasOption("o") || cli.hasOption("output")) {
      outputPath = cli.getOptionValue("dir")
    }
    if(cli.hasOption("mo") || cli.hasOption("module")) {
      module = cli.getOptionValue("name") match {
        case "DATA_LEAKAGE" => TaintAnalysisModules.DATA_LEAKAGE
        case "INTENT_INJECTION" => TaintAnalysisModules.INTENT_INJECTION
        case "PASSWORD_TRACKING" => TaintAnalysisModules.PASSWORD_TRACKING
        case "OAUTH_TOKEN_TRACKING" => TaintAnalysisModules.OAUTH_TOKEN_TRACKING
        case "COMMUNICATION_LEAKAGE" => TaintAnalysisModules.COMMUNICATION_LEAKAGE
      }
    }
    var sourcePath: String = null

    try {
      sourcePath = cli.getArgList.get(1)
    } catch {
      case e: Exception =>
        usage(Mode.TAINT)
        System.exit(0)
    }
    TaintAnalysis(module, debug, sourcePath, outputPath)
  }

  private def cmdApiMisuse(cli: CommandLine) = {
    var debug = false
    var outputPath: String = "."
    var module: ApiMisuseModules.Value = ApiMisuseModules.CRYPTO_MISUSE
    if(cli.hasOption("d") || cli.hasOption("debug")) {
      debug = true
    }
    if(cli.hasOption("o") || cli.hasOption("output")) {
      outputPath = cli.getOptionValue("dir")
    }
    if(cli.hasOption("c") || cli.hasOption("checker")) {
      module = cli.getOptionValue("name") match {
        case "CRYPTO_MISUSE" => ApiMisuseModules.CRYPTO_MISUSE
        case "HIDE_ICON" => ApiMisuseModules.HIDE_ICON
      }
    }
    var sourcePath: String = null

    try {
      sourcePath = cli.getArgList.get(1)
    } catch {
      case e: Exception =>
        usage(Mode.APICHECK)
        System.exit(0)
    }
    ApiMisuse(module, debug, sourcePath, outputPath)
  }

  private def cmdStaging(cli: CommandLine) = {
    var debug = false
    var outputPath: String = "."
    if(cli.hasOption("d") || cli.hasOption("debug")) {
      debug = true
    }
    if(cli.hasOption("o") || cli.hasOption("output")) {
      outputPath = cli.getOptionValue("dir")
    }
    var sourcePath: String = null

    try {
      sourcePath = cli.getArgList.get(1)
    } catch {
      case e: Exception =>
        usage(Mode.STAGE)
        System.exit(0)
    }
    Staging(debug, sourcePath, outputPath)
  }
}
