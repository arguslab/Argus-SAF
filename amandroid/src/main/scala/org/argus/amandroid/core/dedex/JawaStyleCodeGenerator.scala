/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.dedex

import org.argus.jawa.core.util._

import collection.JavaConverters._
import java.util

import hu.ssh.progressbar.ProgressBar
import org.apache.commons.lang3.StringEscapeUtils
import org.argus.amandroid.core.AndroidGlobalConfig
import org.argus.amandroid.core.decompile.DecompileLevel
import org.argus.amandroid.core.dedex.`type`.GenerateTypedJawa
import org.argus.jawa.core.elements.AccessFlag.FlagKind
import org.argus.jawa.core._
import org.argus.jawa.core.codegen.JawaModelProvider
import org.argus.jawa.core.elements._
import org.argus.jawa.core.io.Reporter
import org.jf.dexlib2.dexbacked.instruction.DexBackedInstruction
import org.jf.dexlib2.dexbacked.{DexBackedCatchAllExceptionHandler, DexBackedClassDef, DexBackedDexFile, DexBackedField, DexBackedMethod, DexBackedTryBlock, DexBackedTypedExceptionHandler}
import org.stringtemplate.v4.{ST, STGroupString}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
trait JawaStyleCodeGeneratorListener {
  def onRecordGenerated(recType: JawaType, code: String): Unit = {}
  def onProcedureGenerated(sig: Signature, accessFlag: Int): Unit = {}
  def onInstructionGenerated(round: Int): Unit = {}
  def onGenerateEnd(recordCount: Int, errorOccupied: Boolean): Unit = {}
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class JawaStyleCodeGenerator(ddFile: DexBackedDexFile, filter: JawaType => DecompileLevel.Value, reporter: Reporter) {

  private final val DEBUG_FLOW = false

  val pkgNameMapping: MMap[JawaPackage, String] = mmapEmpty
  val recordNameMapping: MMap[JawaType, String] = mmapEmpty
  val procedureNameMapping: MMap[String, String] = mmapEmpty
  val attributeNameMapping: MMap[(String, JawaType), String] = mmapEmpty
  private var pkgCounter = 0
  private var recordCounter = 0
  private var procedureCounter = 0
  private var attributeCounter = 0
  implicit class StrangeNameResolver(s: String) {
    private def haveStrangeCharacter(str: String): Boolean = {
      StringEscapeUtils.escapeJava(str) != str ||
      str.split("\\.").exists(_.startsWith("0x"))
    }

    def resolveRecord: JawaType = this.synchronized{
      if(haveStrangeCharacter(s)) {
        val sb: StringBuilder = new StringBuilder
        val typ = JavaKnowledge.getTypeFromJawaName(s)
        val pkgList = typ.baseType.pkg match {
          case Some(p) => p.getPkgList
          case None => ilistEmpty
        }
        var recname = typ.baseType.name
        pkgList foreach { pkg =>
          val pkgname = pkg.name
          if(pkgNameMapping.contains(pkg)) {
            sb.append(pkgNameMapping(pkg) + ".")
          } else if(haveStrangeCharacter(pkgname)) {
            val newpkgname = "p" + pkgCounter
            pkgNameMapping(pkg) = newpkgname
            pkgCounter += 1
            sb.append(newpkgname + ".")
          } else sb.append(pkgname + ".")
        }
        if(recordNameMapping.contains(typ)) {
          recname = recordNameMapping(typ)
        } else if(haveStrangeCharacter(recname)) {
          recname = "C" + recordCounter
          recordNameMapping(typ) = recname
          recordCounter += 1
        }
        sb.append(recname)
        new JawaType(sb.toString(), typ.dimensions)
      } else JavaKnowledge.getTypeFromJawaName(s)
    }

    def resolveProcedure: Signature = this.synchronized{
      if(haveStrangeCharacter(s)) {
        val sig = new Signature(s)
        var rectyp = sig.getClassType
        rectyp = rectyp.jawaName.resolveRecord
        var methodName = sig.methodName
        if(procedureNameMapping.contains(sig.getSubSignature)) {
          methodName = procedureNameMapping(sig.getSubSignature)
        } else if(haveStrangeCharacter(methodName)) {
          methodName = "m" + procedureCounter
          procedureNameMapping(sig.getSubSignature) = methodName
          procedureCounter += 1
        }
        val proto = new StringBuilder
        val argTyps = sig.getParameterTypes
        proto.append("(")
        argTyps foreach {
          argTyp =>
            val newArgTyp = argTyp.jawaName.resolveRecord
            val newArgSig = JavaKnowledge.formatTypeToSignature(newArgTyp)
            proto.append(newArgSig)
        }
        proto.append(")")
        var retTyp = sig.getReturnType
        retTyp = retTyp.jawaName.resolveRecord
        val newRetSig = JavaKnowledge.formatTypeToSignature(retTyp)
        proto.append(newRetSig)
        new Signature(rectyp, methodName, proto.toString)
      } else new Signature(s)
    }
    def resolveAttribute(typ: JawaType): FieldFQN = this.synchronized{
      if(haveStrangeCharacter(s) || haveStrangeCharacter(typ.name)) {
        var recTyp = JavaKnowledge.getClassTypeFromFieldFQN(s)
        val fieldName = JavaKnowledge.getFieldNameFromFieldFQN(s)
        var newFieldName = fieldName
        recTyp = recTyp.jawaName.resolveRecord
        if(attributeNameMapping.contains((fieldName, typ))) {
          newFieldName = attributeNameMapping((fieldName, typ))
        } else if(haveStrangeCharacter(fieldName)) {
          newFieldName = "f" + attributeCounter
          attributeNameMapping((fieldName, typ)) = newFieldName
          attributeCounter += 1
        }
        val fieldTyp = typ.jawaName.resolveRecord
        JavaKnowledge.generateFieldFQN(recTyp, newFieldName, fieldTyp)
      } else {
        val recTyp = JavaKnowledge.getClassTypeFromFieldFQN(s)
        val fieldName = JavaKnowledge.getFieldNameFromFieldFQN(s)
        JavaKnowledge.generateFieldFQN(recTyp, fieldName, typ)
      }
    }
  }

  def generate(listener: Option[JawaStyleCodeGeneratorListener] = None, progressBar: ProgressBar): IMap[JawaType, String] = {
    val result: MMap[JawaType, String] = mmapEmpty
    val needType: MMap[JawaType, String] = mmapEmpty
    val dexClasses = ddFile.getClasses.asScala.toSet
    var errorOccurred = false
    def handleClass: DexBackedClassDef => Unit = { dexClass =>
      val recType: JawaType = JavaKnowledge.formatSignatureToType(dexClass.getType).jawaName.resolveRecord
      val level = filter(recType)
      if (level > DecompileLevel.NO) {
        val genBody = level > DecompileLevel.SIGNATURE
        process(dexClass, recType, listener, genBody) match {
          case Some((typ, code)) =>
            if(level >= DecompileLevel.TYPED) {
              needType(typ) = code
            } else {
              result(typ) = code
            }
          case None =>
            errorOccurred = true
        }
      }
    }
    ProgressBarUtil.withProgressBar("Dedexing...", progressBar)(dexClasses, handleClass)

    def handleType(global: Global): ((JawaType, String)) => (JawaType, String) = { case (typ, code) =>
      val newcode = try {
        GenerateTypedJawa(code, global)
      } catch {
        case e: Exception =>
          if (DEBUG_FLOW) e.printStackTrace()
          errorOccurred = true
          code
      }
      (typ, newcode)
    }
    if(needType.nonEmpty) {
      val global = new Global("Type", reporter)
      global.setJavaLib(AndroidGlobalConfig.settings.lib_files)
      val codes: IMap[JawaType, String] = (result ++ needType).toMap
      global.loadJawaCode(codes)
      result ++= ProgressBarUtil.withProgressBar("Resolving types...", progressBar)(needType.toSet, handleType(global))
    }
    if(listener.isDefined) listener.get.onGenerateEnd(result.size, errorOccurred)
    result.toMap
  }

  private def process(dexClass: DexBackedClassDef, recType: JawaType, listener: Option[JawaStyleCodeGeneratorListener], genBody: Boolean): Option[(JawaType, String)] = {
    val template = new STGroupString(JawaModelProvider.jawaModel)
    if (DEBUG_FLOW) {
      println("Processing " + recType)
    }
    try {
      val code = generateRecord(dexClass, recType, listener, genBody, template)
      Some((recType, code))
    } catch {
      case e: Exception =>
        if(DEBUG_FLOW) {
          e.printStackTrace()
        }
        None
    }
  }

  private def generateRecord(dexClass: DexBackedClassDef, recTyp: JawaType, listener: Option[JawaStyleCodeGeneratorListener], genBody: Boolean, template: STGroupString): String = {
    val recTemplate = template.getInstanceOf("RecordDecl")
    val accessFlagInt: Int = AccessFlag.getJawaFlags(dexClass.getAccessFlags, FlagKind.CLASS, isConstructor = false)
    val isInterface: Boolean = AccessFlag.isInterface(accessFlagInt)
    val accessFlag: String = getAccessString(AccessFlag.toString(accessFlagInt))
    val superClass: Option[JawaType] = Option(dexClass.getSuperclass).map(s => JavaKnowledge.formatSignatureToType(s).jawaName.resolveRecord)
    val interfaceClasses: IList[JawaType] = dexClass.getInterfaces.asScala.map { interface =>
      JavaKnowledge.formatSignatureToType(interface).jawaName.resolveRecord
    }.toList
    recTemplate.add("recName", recTyp.jawaName)
    val recAnnotations = new util.ArrayList[ST]
    recAnnotations.add(JawaModelProvider.generateAnnotation("kind", if(isInterface) "interface" else "class", template))
    recAnnotations.add(JawaModelProvider.generateAnnotation("AccessFlag", accessFlag, template))
    recTemplate.add("annotations", recAnnotations)

    val extendsList: util.ArrayList[ST] = new util.ArrayList[ST]
    superClass foreach { sc =>
      if(sc.jawaName != "java.lang.Object") {
        val extOrImpTemplate = template.getInstanceOf("ExtendsAndImplements")
        extOrImpTemplate.add("recName", sc.jawaName)
        val extAnnotations = new util.ArrayList[ST]
        extAnnotations.add(JawaModelProvider.generateAnnotation("kind", "class", template))
        extOrImpTemplate.add("annotations", extAnnotations)
        extendsList.add(extOrImpTemplate)
      }
    }
    interfaceClasses foreach { ic =>
      val extOrImpTemplate = template.getInstanceOf("ExtendsAndImplements")
      extOrImpTemplate.add("recName", ic.jawaName)
      val impAnnotations = new util.ArrayList[ST]
      impAnnotations.add(JawaModelProvider.generateAnnotation("kind", "interface", template))
      extOrImpTemplate.add("annotations", impAnnotations)
      extendsList.add(extOrImpTemplate)
    }
    recTemplate.add("extends", extendsList)
    recTemplate.add("attributes", generateAttributes(recTyp, dexClass.getInstanceFields.asScala.toList, template))
    recTemplate.add("globals", generateGlobals(recTyp, dexClass.getStaticFields.asScala.toList, template))
    recTemplate.add("procedures", generateProcedures(recTyp, dexClass.getMethods.asScala.toList, listener, genBody, template))
    val code = recTemplate.render()
    if(listener.isDefined) listener.get.onRecordGenerated(recTyp, code)
    code
  }

  private def generateAttributes(classType: JawaType, dexFields: IList[DexBackedField], template: STGroupString): util.ArrayList[ST] = {
    val attributes: util.ArrayList[ST] = new util.ArrayList[ST]
    dexFields.foreach { dexField =>
      val attrName = classType.jawaName + "." + dexField.getName
      val attrType = JavaKnowledge.formatSignatureToType(dexField.getType).jawaName.resolveRecord
      val fqn = attrName.resolveAttribute(attrType)
      val accessFlagInt: Int = AccessFlag.getJawaFlags(dexField.getAccessFlags, FlagKind.FIELD, isConstructor = false)
      val accessFlag = getAccessString(AccessFlag.toString(accessFlagInt))
      val attrTemplate = template.getInstanceOf("AttributeDecl")
      attrTemplate.add("attrTyp", JawaModelProvider.generateType(fqn.typ, template))
      attrTemplate.add("attrName", fqn.fqn)
      val attrAnnotations = new util.ArrayList[ST]
      attrAnnotations.add(JawaModelProvider.generateAnnotation("AccessFlag", accessFlag, template))
      attrTemplate.add("annotations", attrAnnotations)
      attributes.add(attrTemplate)
    }
    attributes
  }

  private def generateGlobals(classType: JawaType, dexFields: IList[DexBackedField], template: STGroupString): util.ArrayList[ST] = {
    val globals: util.ArrayList[ST] = new util.ArrayList[ST]
    dexFields.foreach { dexField =>
      val globalName = classType.jawaName + "." + dexField.getName
      val globalType = JavaKnowledge.formatSignatureToType(dexField.getType).jawaName.resolveRecord
      val fqn = globalName.resolveAttribute(globalType)
      val accessFlagInt: Int = AccessFlag.getJawaFlags(dexField.getAccessFlags, FlagKind.FIELD, isConstructor = false)
      val accessFlag = getAccessString(AccessFlag.toString(accessFlagInt))
      val globalTemplate = template.getInstanceOf("GlobalDecl")
      globalTemplate.add("globalTyp", JawaModelProvider.generateType(fqn.typ, template))
      globalTemplate.add("globalName", "@@" + fqn.fqn)
      val globalAnnotations = new util.ArrayList[ST]
      globalAnnotations.add(JawaModelProvider.generateAnnotation("AccessFlag", accessFlag, template))
      globalTemplate.add("annotations", globalAnnotations)
      globals.add(globalTemplate)
    }
    globals
  }

  private def generateProcedures(classType: JawaType, dexMethods: IList[DexBackedMethod], listener: Option[JawaStyleCodeGeneratorListener], genBody: Boolean, template: STGroupString): util.ArrayList[ST] = {
    val procedures: util.ArrayList[ST] = new util.ArrayList[ST]
    dexMethods foreach { dexMethod =>
      procedures.add(generateProcedure(classType, dexMethod, listener, genBody, template))
    }
    procedures
  }

  private def getSignature(classTyp: JawaType, dexMethod: DexBackedMethod): Signature = {
    val retTyp: JawaType = JavaKnowledge.formatSignatureToType(dexMethod.getReturnType).jawaName.resolveRecord
    val paramList: IList[JawaType] = dexMethod.getParameterTypes.asScala.map(JavaKnowledge.formatSignatureToType(_).jawaName.resolveRecord).toList
    JavaKnowledge.genSignature(classTyp, dexMethod.getName, paramList, retTyp).signature.resolveProcedure
  }

  private def generateProcedure(classType: JawaType, dexMethod: DexBackedMethod, listener: Option[JawaStyleCodeGeneratorListener], genBody: Boolean, template: STGroupString): ST = {
    val sig = getSignature(classType, dexMethod)
    val procName = sig.methodName
    val retTyp = sig.getReturnType
    val isConstructor: Boolean = procName == "<init>" || procName == "<clinit>"
    val accessFlagInt: Int = AccessFlag.getJawaFlags(dexMethod.accessFlags, FlagKind.METHOD, isConstructor)
    val accessFlags = getAccessString(AccessFlag.toString(accessFlagInt))

    var baseReg = 0
    val dexImpl = dexMethod.getImplementation
    if(dexImpl != null) baseReg = dexImpl.getRegisterCount - dexMethod.getParameters.size - sig.getParameterTypes.count(_.isDWordPrimitive)
    var paramReg = baseReg
    var thisOpt: Option[(String, JawaType)] = None

    if(!AccessFlag.isAbstract(accessFlagInt) && !AccessFlag.isStatic(accessFlagInt) && !AccessFlag.isNative(accessFlagInt)) {
      baseReg -= 1
      thisOpt = Some(("v" + baseReg, classType))
    }
    val paramList: IList[(String, String, JawaType)] = dexMethod.getParameters.asScala.map { dexParam =>
      val paramTyp: JawaType = JavaKnowledge.formatSignatureToType(dexParam.getType).jawaName.resolveRecord
      val regName = "v" + paramReg
      val paramName = dexParam.getName
      paramReg += 1
      if(paramTyp.isDWordPrimitive) paramReg += 1
      (regName, paramName, paramTyp)
    }.toList

    val procTemplate = template.getInstanceOf("ProcedureDecl")
    procTemplate.add("retTyp", JawaModelProvider.generateType(retTyp, template))
    procTemplate.add("procedureName", procName)
    val params: util.ArrayList[ST] = new util.ArrayList[ST]
    thisOpt foreach {
      case (thisName, thisTyp) =>
        val paramTemplate = template.getInstanceOf("Param")
        paramTemplate.add("paramTyp", JawaModelProvider.generateType(thisTyp, template))
        paramTemplate.add("paramName", thisName)
        val thisAnnotations = new util.ArrayList[ST]
        thisAnnotations.add(JawaModelProvider.generateAnnotation("kind", "this", template))
        paramTemplate.add("annotations", thisAnnotations)
        params.add(paramTemplate)
    }
    paramList foreach {
      case (regName, paramName, paramTyp) =>
        val paramTemplate = template.getInstanceOf("Param")
        paramTemplate.add("paramTyp", JawaModelProvider.generateType(paramTyp, template))
        paramTemplate.add("paramName", regName)
        val paramAnnotations = new util.ArrayList[ST]
        if(paramTyp.isObject) {
          paramAnnotations.add(JawaModelProvider.generateAnnotation("kind", "object", template))
        }
        if(paramName != null) paramAnnotations.add(JawaModelProvider.generateAnnotation("name", "`" + paramName + "`", template))
        paramTemplate.add("annotations", paramAnnotations)
        params.add(paramTemplate)
    }
    procTemplate.add("params", params)
    val procAnnotations = new util.ArrayList[ST]
    procAnnotations.add(JawaModelProvider.generateAnnotation("signature", "`" + sig.signature + "`", template))
    procAnnotations.add(JawaModelProvider.generateAnnotation("AccessFlag", accessFlags, template))
    procTemplate.add("annotations", procAnnotations)
    if(genBody && !AccessFlag.isAbstract(AccessFlag.getAccessFlags(accessFlags)) &&
        !AccessFlag.isNative(AccessFlag.getAccessFlags(accessFlags))) {
      val (body, tryCatch) = generateBody(dexMethod, listener, template)
      procTemplate.add("localVars", generateLocalVars(baseReg, template))
      procTemplate.add("body", body)
      procTemplate.add("catchClauses", tryCatch)
    } else {
      procTemplate.add("body", "# return;")
    }
    if(listener.isDefined) listener.get.onProcedureGenerated(sig, accessFlagInt)
    procTemplate
  }

  private def generateLocalVars(baseReg: Int, template: STGroupString): ST = {
    val localVarsTemplate: ST = template.getInstanceOf("LocalVars")
    val locals: util.ArrayList[String] = new util.ArrayList[String]
    locals.add("temp;")
    (0 until baseReg).foreach {
      reg =>
        val regName = "v" + reg + ";"
        locals.add(regName)
    }
    localVarsTemplate.add("locals", locals)
    localVarsTemplate
  }

  private def generateBody(dexMethod: DexBackedMethod, listener: Option[JawaStyleCodeGeneratorListener], template: STGroupString): (ST, ST) = {
    val bodyTemplate: ST = template.getInstanceOf("Body")
    val catchesTemplate: ST = template.getInstanceOf("CatchClauses")
    val instructions = dexMethod.getImplementation.getInstructions.asScala.map(_.asInstanceOf[DexBackedInstruction])

    val start: Long = instructions.head.instructionStart
    val end: Long = instructions.last.instructionStart + instructions.last.getCodeUnits * 2L

    val tryBlocks = dexMethod.getImplementation.getTryBlocks
    val exceptionTypeMap = processTryCatchBlock(catchesTemplate, tryBlocks.asScala.toList, start, template)

    val codes: util.ArrayList[String] = new util.ArrayList[String]
    val instructionParser = DexInstructionToJawaParser(dexMethod, this, exceptionTypeMap, template)

    instructions.foreach { inst =>
//      labels.get(inst.instructionStart) match {
//        case Some(label) =>
//          label.foreach(l => codes.add("#%s.  ".format(l)))
//        case None =>
//      }
      codes.add(instructionParser.parse(inst, start, end))
    }
//    labels.get(end) match {
//      case Some(label) =>
//        label.foreach(l => codes.add("#%s.  ".format(l)))
//      case None =>
//    }
    bodyTemplate.add("codeFragments", codes)
    (bodyTemplate, catchesTemplate)
  }
 

  def writeTryCatchBlock(catchTemplate: ST, startLabel: String, endLabel: String, exception: JawaType, handlerLabel: String, template: STGroupString): ST = {
    catchTemplate.add("catchTyp", JawaModelProvider.generateType(exception, template))
    catchTemplate.add("fromLoc", startLabel)
    catchTemplate.add("toLoc", endLabel)
    catchTemplate.add("targetLoc", handlerLabel)
    catchTemplate
  }
  
  private def processTryCatchBlock(
      catchesTemplate: ST,
      tryBlocks: IList[DexBackedTryBlock],
      base: Long,
      template: STGroupString): IMap[Long, JawaType] = {
    val typeMap: MMap[Long, JawaType] = mmapEmpty
    val catches: util.ArrayList[ST] = new util.ArrayList[ST]
    var i = 0
    for(tryBlock <- tryBlocks) {
      val start: Long = base + tryBlock.getStartCodeAddress * 2L
      val end: Long = start + tryBlock.getCodeUnitCount * 2L
      val startLabel: String = "L%06x".format(start)
      val endLabel: String =  "L%06x".format(end)
      for(handler <- tryBlock.getExceptionHandlers.asScala) {
        val catchTemplate: ST = template.getInstanceOf("Catch")
        val exceptionType: JawaType = handler match {
          case dbteh: DexBackedTypedExceptionHandler => JavaKnowledge.formatSignatureToType(dbteh.getExceptionType).jawaName.resolveRecord
          case _: DexBackedCatchAllExceptionHandler => new JawaType("java.lang.Throwable")
        }
        val handlerOffset: Long = base + handler.getHandlerCodeAddress * 2L
        typeMap(handlerOffset) = exceptionType
        val handlerLabel = "L%06x".format(handlerOffset)
        writeTryCatchBlock(catchTemplate, startLabel, endLabel, exceptionType, handlerLabel, template)
        catches.add(catchTemplate)
      }
      i += 1
    }
    catchesTemplate.add("catches", catches)
    typeMap.toMap
  }

  private def getAccessString(name: String): String = {
    name.split(" ").map(_.toUpperCase).mkString("_")
  }
}
