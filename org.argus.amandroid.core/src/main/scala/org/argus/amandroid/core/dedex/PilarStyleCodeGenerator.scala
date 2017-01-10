/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.dedex

import org.sireum.util._
import hu.uw.pallergabor.dedexer._
import java.io.RandomAccessFile
import java.io.PrintStream

import collection.JavaConversions._
import java.io.IOException
import java.util

import org.apache.commons.lang.StringEscapeUtils
import org.argus.amandroid.core.dedex.DedexTypeResolver.{DedexJawaType, DedexType, DedexUndeterminedType}
import org.argus.amandroid.core.dedex.DexInstructionToPilarParser.ForkStatus
import org.argus.jawa.core._
import org.argus.jawa.core.util.MyFileUtil
import org.stringtemplate.v4.{ST, STGroupString}

import scala.util.control.Breaks._

/**
 * Be aware that if you using this listener, the record code will not write to file automatically.
 * Basically the idea is you should handle that by yourself.
 * 
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
trait PilarStyleCodeGeneratorListener {
  def onRecordGenerated(recType: JawaType, code: String, outputUri: Option[FileResourceUri])
  def onGenerateEnd(recordCount: Int)
}

object PilarStyleCodeGenerator {
  def outputCode(recType: JawaType, code: String, outputUri: Option[FileResourceUri]) = {
    val classPath = recType.jawaName.replaceAll("\\.", "/")
    val outputStream = outputUri match {
      case Some(od) =>
        var targetFile = FileUtil.toFile(MyFileUtil.appendFileName(od, classPath + ".jawa"))
        var i = 0
        while(targetFile.exists()){
          i += 1
          targetFile = FileUtil.toFile(MyFileUtil.appendFileName(od, classPath + "." + i + ".jawa"))
        }
        val parent = targetFile.getParentFile
        if(parent != null)
          parent.mkdirs()
        new PrintStream(targetFile)
      case None =>
        new PrintStream(System.out)
    }
    outputStream.println(code)
    outputUri match {
      case Some(t) => outputStream.close()
      case _ =>
    }
  }
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class PilarStyleCodeGenerator(
    dexSignatureBlock: DexSignatureBlock,
    dexStringIdsBlock: DexStringIdsBlock,
    dexTypeIdsBlock: DexTypeIdsBlock,
    dexFieldIdsBlock: DexFieldIdsBlock,
    dexMethodIdsBlock: DexMethodIdsBlock,
    dexClassDefsBlock: DexClassDefsBlock,
    dexOffsetResolver: DexOffsetResolver,
    file: RandomAccessFile,
    outputUri: Option[FileResourceUri],
    dump: Option[PrintStream],
    filter: (JawaType => Boolean)) {
  
  import PilarStyleCodeGenerator._
  
  private final val DEBUG_EXCP = false
  private final val DEBUG_REGMAPS = false
  private final val DEBUG_REGTRACE = false
//  private final val DEBUG_MERGE = false
  private final val DEBUG_FLOW = false
//  private final val REVISIT_LIMIT = 20
  
  protected val template = new STGroupString(PilarModelProvider.pilarModel)
//  private var procDeclTemplate = template.getInstanceOf("ProcedureDecl")
//  private var localVarsTemplate = template.getInstanceOf("LocalVars")
  
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
    
    def resolveRecord: JawaType = {
      if(haveStrangeCharacter(s)) {
        val sb: StringBuilder = new StringBuilder
        val typ = JavaKnowledge.getTypeFromJawaName(s)
        val pkgList = typ.baseType.pkg match {
          case Some(p) => p.getPkgList
          case None => ilistEmpty
        }
        var recname = typ.baseType.name
        pkgList foreach {
          pkg =>
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
    
    def resolveProcedure: Signature = {
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
        Signature(rectyp, methodName, proto.toString)
      } else new Signature(s)
    }
    def resolveAttribute(typ: JawaType): FieldFQN = {
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
  
  def generate(listener: Option[PilarStyleCodeGeneratorListener] = None): IMap[JawaType, String] = {
    val result: MMap[JawaType, String] = mmapEmpty
    val classreader = dexClassDefsBlock.getClassIterator
    while(classreader.hasNext) {
      val classIdx = classreader.next().intValue()
      val recType: JawaType = toPilarRecordName(dexClassDefsBlock.getClassNameOnly(classIdx)).resolveRecord
      if(filter(recType)) {
        if(DEBUG_FLOW)
          println("Processing " + recType)
        if(dump.isDefined) {
          dump.get.println("--------------------------------------")
          dump.get.println("Class: " + recType)
        }
        val code = generateRecord(classIdx)
        result(recType) = code
        if(listener.isDefined) listener.get.onRecordGenerated(recType, code, outputUri)
        else outputCode(recType, code, outputUri)
      }
    }
    if(listener.isDefined) listener.get.onGenerateEnd(result.size)
    result.toMap
  }
  
  private def generateAnnotation(flag: String, value: String): ST = {
    val annot = template.getInstanceOf("Annotation")
    annot.add("flag", flag)
    annot.add("value", value)
  }
  
  def generateType(typ: JawaType): ST = {
    val typTemplate = template.getInstanceOf("Type")
    typTemplate.add("baseTyp", typ.baseTyp)
    val dimensions: util.ArrayList[String] = new util.ArrayList[String]
    for(i <- 0 until typ.dimensions) dimensions.add("[]")
    typTemplate.add("dimensions", dimensions)
    typTemplate
  }
  
  private def generateRecord(classIdx: Int): String = {
    val recTemplate = template.getInstanceOf("RecordDecl")
    val recTyp: JawaType = toPilarRecordName(dexClassDefsBlock.getClassNameOnly(classIdx)).resolveRecord
    val isInterface: Boolean = dexClassDefsBlock.isInterface(classIdx)
    val accessFlag: String = getAccessString(dexClassDefsBlock.getClassName(classIdx), skip = 1, isInterface, isConstructor = false)
    val superClass: Option[JawaType] = Option(dexClassDefsBlock.getSuperClass(classIdx)).map(toPilarRecordName(_).resolveRecord)
    val interfaceClasses: MSet[JawaType] = msetEmpty
    for(i <- 0 until dexClassDefsBlock.getInterfacesSize(classIdx))
      interfaceClasses += toPilarRecordName(dexClassDefsBlock.getInterface(classIdx, i)).resolveRecord
    recTemplate.add("recName", recTyp.jawaName)
    val recAnnotations = new util.ArrayList[ST]
    recAnnotations.add(generateAnnotation("kind", if(isInterface) "interface" else "class"))
    recAnnotations.add(generateAnnotation("AccessFlag", accessFlag))
    recTemplate.add("annotations", recAnnotations)
    
    val extendsList: util.ArrayList[ST] = new util.ArrayList[ST]
    superClass foreach {
      sc =>
        if(sc.jawaName != "java.lang.Object") {
          val extOrImpTemplate = template.getInstanceOf("ExtendsAndImpliments")
          extOrImpTemplate.add("recName", sc.jawaName)
          val extAnnotations = new util.ArrayList[ST]
          extAnnotations.add(generateAnnotation("kind", "class"))
          extOrImpTemplate.add("annotations", extAnnotations)
          extendsList.add(extOrImpTemplate)
        }
    }
    interfaceClasses foreach {
      ic =>
        val extOrImpTemplate = template.getInstanceOf("ExtendsAndImpliments")
        extOrImpTemplate.add("recName", ic.jawaName)
        val impAnnotations = new util.ArrayList[ST]
        impAnnotations.add(generateAnnotation("kind", "interface"))
        extOrImpTemplate.add("annotations", impAnnotations)
        extendsList.add(extOrImpTemplate)
    }
    recTemplate.add("extends", extendsList)
    recTemplate.add("attributes", generateAttributes(classIdx))
    recTemplate.add("globals", generateGlobals(classIdx))
    recTemplate.add("procedures", generateProcedures(classIdx))
    recTemplate.render()
  }
  
  private def generateAttributes(classIdx: Int): util.ArrayList[ST] = {
    val attributes: util.ArrayList[ST] = new util.ArrayList[ST]
    val recName: String = toPilarRecordName(dexClassDefsBlock.getClassNameOnly(classIdx))
    for(fieldIdx <- 0 until dexClassDefsBlock.getInstanceFieldsSize(classIdx)) {
      val attrName = recName + "." + dexClassDefsBlock.getInstanceFieldShortName(classIdx, fieldIdx)
      val attrType = getFieldType(dexClassDefsBlock.getInstanceFieldNameAndType(classIdx, fieldIdx))
      val fqn = attrName.resolveAttribute(attrType)
      val accessFlag = getAccessString(dexClassDefsBlock.getInstanceField(classIdx, fieldIdx), skip = 2, isInterface = false, isConstructor = false)
      val attrTemplate = template.getInstanceOf("AttributeDecl")
      attrTemplate.add("attrTyp", generateType(fqn.typ))
      attrTemplate.add("attrName", fqn.fqn)
      val attrAnnotations = new util.ArrayList[ST]
      attrAnnotations.add(generateAnnotation("AccessFlag", accessFlag))
      attrTemplate.add("annotations", attrAnnotations)
      attributes.add(attrTemplate)
    }
    attributes
  }
  
  private def generateGlobals(classIdx: Int): util.ArrayList[ST] = {
    val globals: util.ArrayList[ST] = new util.ArrayList[ST]
    val recName: String = toPilarRecordName(dexClassDefsBlock.getClassNameOnly(classIdx))
    for(fieldIdx <- 0 until dexClassDefsBlock.getStaticFieldsSize(classIdx)) {
      val globalName = recName + "." + dexClassDefsBlock.getStaticFieldShortName(classIdx, fieldIdx)
      val globalType = getFieldType(dexClassDefsBlock.getStaticField(classIdx, fieldIdx))
      val fqn = globalName.resolveAttribute(globalType)
      val accessFlag = getAccessString(dexClassDefsBlock.getStaticField(classIdx, fieldIdx), skip = 2, isInterface = false, isConstructor = false)
      val globalTemplate = template.getInstanceOf("GlobalDecl")
      globalTemplate.add("globalTyp", generateType(fqn.typ))
      globalTemplate.add("globalName", "@@" + fqn.fqn)
      val globalAnnotations = new util.ArrayList[ST]
      globalAnnotations.add(generateAnnotation("AccessFlag", accessFlag))
      globalTemplate.add("annotations", globalAnnotations)
      globals.add(globalTemplate)
    }
    globals
  }
  
  private def generateProcedures(classIdx: Int): util.ArrayList[ST] = {
    val procedures: util.ArrayList[ST] = new util.ArrayList[ST]
    
    for(methodIdx <- 0 until dexClassDefsBlock.getDirectMethodsFieldsSize(classIdx)) {
      procedures.add(generateProcedure(classIdx, methodIdx, isDirect = true))
    }
    for(methodIdx <- 0 until dexClassDefsBlock.getVirtualMethodsFieldsSize(classIdx)) {
      procedures.add(generateProcedure(classIdx, methodIdx, isDirect = false))
    }
    procedures
  }
  
  private def getSignature(dexMethodHeadParser: DexMethodHeadParser, paramRegs: util.ArrayList[_], classIdx: Int, methodIdx: Int, isDirect: Boolean): (Signature, IList[Int]) = {
    val recName: String = toPilarRecordName(dexClassDefsBlock.getClassNameOnly(classIdx))
    val recTyp: JawaType = new JawaType(recName)
    val retTyp: JawaType = 
      if(isDirect) getReturnType(dexClassDefsBlock.getDirectMethodName(classIdx, methodIdx))
      else getReturnType(dexClassDefsBlock.getVirtualMethodName(classIdx, methodIdx))
//    val procName: String =
//      if(isDirect) recName + "." + dexClassDefsBlock.getDirectMethodShortName(classIdx, methodIdx)
//      else recName + "." + dexClassDefsBlock.getVirtualMethodShortName(classIdx, methodIdx)
    val paramList: MList[JawaType] = mlistEmpty
    val paramRegNumbers: MList[Int] = mlistEmpty
    for(i <- 0 until paramRegs.size() by + 2) {
      val paramReg = paramRegs.get(i).asInstanceOf[Integer]
      paramRegNumbers += paramReg
      val paramTypSig = paramRegs.get(i+1).asInstanceOf[String]
      val paramTyp: JawaType = 
        if(paramTypSig.isEmpty) JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE
        else JavaKnowledge.formatSignatureToType(paramTypSig)
      paramList += paramTyp
    }
    val sig: Signature = 
      if(isDirect) JavaKnowledge.genSignature(recTyp, dexClassDefsBlock.getDirectMethodShortName(classIdx, methodIdx), paramList.toList, retTyp)
      else JavaKnowledge.genSignature(recTyp, dexClassDefsBlock.getVirtualMethodShortName(classIdx, methodIdx), paramList.toList, retTyp)
    val newSig = sig.signature.resolveProcedure
    (newSig, paramRegNumbers.toList)
  }
  
  private def generateProcedure(classIdx: Int, methodIdx: Int, isDirect: Boolean): ST = {
    val pos: Long = 
      if(isDirect) dexClassDefsBlock.getDirectMethodOffset(classIdx, methodIdx)
      else dexClassDefsBlock.getVirtualMethodOffset(classIdx, methodIdx)
    val dexMethodHeadParser = new DexMethodHeadParser()
    dexMethodHeadParser.setRandomAccessFile(file)
    dexMethodHeadParser.setDexSignatureBlock(dexSignatureBlock)
    dexMethodHeadParser.setDumpFile(dump.orNull)
    dexMethodHeadParser.parse(pos)
    val regSize: Int = dexMethodHeadParser.getRegistersSize
    val paramRegs = 
      if(isDirect) dexClassDefsBlock.getDirectMethodParameterOffsets(classIdx, methodIdx, regSize)
      else dexClassDefsBlock.getVirtualMethodParameterOffsets(classIdx, methodIdx, regSize)
    val (sig, paramRegNums) = getSignature(dexMethodHeadParser, paramRegs, classIdx, methodIdx, isDirect)
    val recTyp = sig.classTyp
    val procName = sig.classTyp.name + "." + sig.methodName
    val retTyp = sig.getReturnType
    val isConstructor: Boolean = procName.contains("<init>") || procName.contains("<clinit>")
    val accessFlags = 
      if(isDirect) getAccessString(dexClassDefsBlock.getDirectMethodName(classIdx, methodIdx), skip = 1, isInterface = false, isConstructor = isConstructor)
      else getAccessString(dexClassDefsBlock.getVirtualMethodName(classIdx, methodIdx), skip = 1, isInterface = false, isConstructor = isConstructor)
    var thisOpt: Option[(String, JawaType)] = None
    val initRegMap: MMap[Int, DedexType] = mmapEmpty
    val localvars: MMap[String, (JawaType, Boolean)] = mmapEmpty
    if(!AccessFlag.isStatic(AccessFlag.getAccessFlags(accessFlags))) {
      var thisReg = 0
      if(paramRegs.size() < 2)   // no parameters - "this" is in the last register
        thisReg = regSize - 1
      else
        thisReg = paramRegs.get(0).asInstanceOf[Integer].intValue() - 1
      var thisName = recTyp.baseTyp.substring(recTyp.baseTyp.lastIndexOf(".") + 1) + {if(recTyp.dimensions > 0)"_arr" + recTyp.dimensions else ""} + "_v" + thisReg
      if(localvars.contains(thisName) && localvars(thisName)._1 != recTyp) thisName = "a" + thisName
      localvars(thisName) = (recTyp, true)
      thisOpt = Some((thisName, recTyp))
      initRegMap(thisReg) = DedexJawaType(recTyp)
    }
    val paramList: MList[(String, JawaType)] = mlistEmpty
    val paramTyps = sig.getParameterTypes
    for(i <- paramRegNums.indices) {
      val paramReg = paramRegNums(i)
      val paramTyp: JawaType = paramTyps(i)
      var paramName = paramTyp.baseTyp.substring(paramTyp.baseTyp.lastIndexOf(".") + 1) + {if(paramTyp.dimensions > 0)"_arr" + paramTyp.dimensions else ""} + "_v" + paramReg
      if(localvars.contains(paramName) && localvars(paramName)._1 != paramTyp) paramName = "a" + paramName
      localvars(paramName) = (paramTyp, true)
      paramList += ((paramName, paramTyp))
      initRegMap(paramReg) = DedexJawaType(paramTyp)
    }
    
    val procTemplate = template.getInstanceOf("ProcedureDecl")
//    if(sig.signature == "Lavm;.a:([B)[B") {
    procTemplate.add("retTyp", generateType(retTyp))
    procTemplate.add("procedureName", procName)
    val params: util.ArrayList[ST] = new util.ArrayList[ST]
    if(!AccessFlag.isAbstract(AccessFlag.getAccessFlags(accessFlags))) {
      thisOpt foreach {
        case (thisName, thisTyp) =>
          val paramTemplate = template.getInstanceOf("Param")
          paramTemplate.add("paramTyp", generateType(thisTyp))
          paramTemplate.add("paramName", thisName)
          val thisAnnotations = new util.ArrayList[ST]
          thisAnnotations.add(generateAnnotation("kind", "this"))
          paramTemplate.add("annotations", thisAnnotations)
          params.add(paramTemplate)
      }
    }
    paramList foreach {
      case (paramName, paramTyp) =>
        val paramTemplate = template.getInstanceOf("Param")
        paramTemplate.add("paramTyp", generateType(paramTyp))
        paramTemplate.add("paramName", paramName)
        val paramAnnotations = new util.ArrayList[ST]
        if(!JavaKnowledge.isJavaPrimitive(paramTyp)) {
          paramAnnotations.add(generateAnnotation("kind", "object"))
        }
        paramTemplate.add("annotations", paramAnnotations)
        params.add(paramTemplate)
    }
    procTemplate.add("params", params)
    val procAnnotations = new util.ArrayList[ST]
    procAnnotations.add(generateAnnotation("owner", "^" + generateType(recTyp).render()))
    procAnnotations.add(generateAnnotation("signature", "`" + sig.signature + "`"))
    procAnnotations.add(generateAnnotation("AccessFlag", accessFlags))
    procTemplate.add("annotations", procAnnotations)
    if(!AccessFlag.isAbstract(AccessFlag.getAccessFlags(accessFlags)) &&
        !AccessFlag.isNative(AccessFlag.getAccessFlags(accessFlags))) {
      val (body, tryCatch) = generateBody(sig, procName, dexMethodHeadParser, initRegMap, localvars)
      procTemplate.add("localVars", generateLocalVars(localvars.toMap))
      procTemplate.add("body", body)
      procTemplate.add("catchClauses", tryCatch)
    } else {
      procTemplate.add("body", "#. return;")
    }
//    }
    procTemplate
  }
  
  private def generateLocalVars(localvars: IMap[String, (JawaType, Boolean)]): ST = {
    val localVarsTemplate: ST = template.getInstanceOf("LocalVars")
    val locals: util.ArrayList[String] = new util.ArrayList[String]
    localvars.foreach {
      case (name, (typ, param)) =>
        if(!param) {
          val regName = generateType(typ).render() + " " + name + ";"
          locals += regName
        }
    }
    localVarsTemplate.add("locals", locals)
    localVarsTemplate
  }
  
  private def generateBody(sig: Signature, procName: String, dexMethodHeadParser: DexMethodHeadParser, initRegMap: MMap[Int, DedexType], localvars: MMap[String, (JawaType, Boolean)]): (ST, ST) = {    
    val bodyTemplate: ST = template.getInstanceOf("Body")
    val startPos: Long = dexMethodHeadParser.getInstructionBase
    val endPos: Long = dexMethodHeadParser.getInstructionEnd
    val codes: util.ArrayList[String] = new util.ArrayList[String]
    val instructionParser = 
      new DexInstructionToPilarParser(
          sig,
          this,
          dexSignatureBlock, 
          dexStringIdsBlock, 
          dexTypeIdsBlock, 
          dexFieldIdsBlock, 
          dexMethodIdsBlock, 
          dexOffsetResolver)
    instructionParser.setDumpFile(dump.orNull)
    instructionParser.setRandomAccessFile(file)
    instructionParser.setDumpOff()
    // First pass: discover just the labels and the code areas. The trace disassembler
    // simulates the instruction flow and discovers code/data areas.
    
    // Each bit represents the starting offset of an instruction in the
    // method body. 
    val visitSet = new util.BitSet((endPos - startPos).asInstanceOf[Int])
    // Branches in the execution flow are stored in this stack
    val visitStack = new util.Stack[VisitStackEntry]()
    
    // This map stores the exception block start addresses and the associated exception 
    // handlers
    val exceptionHandlerEntryPointList: MList[ExceptionHandlerMapEntry] = mlistEmpty

    // This map stores the saved register maps for distinguished locations.
    // Targets of jump instructions are such locations.
    val registerMaps: MMap[Long, MMap[Int, MSet[DedexUndeterminedType]]] = mmapEmpty

    // Process the try-catch blocks if any. Pushes any exception handlers to the visit stack
    if(DEBUG_FLOW)
      println("Flow: about to process try-catch blocks")
    val catchsTemplate: ST = template.getInstanceOf("CatchClauses")
    if(dexMethodHeadParser.getTriesSize != 0){
      processTryCatchBlock(
          procName,
          catchsTemplate,
          instructionParser, 
          dexMethodHeadParser,
          visitStack,
          initRegMap,
          exceptionHandlerEntryPointList)
    }
    var debugInfoParser: DexDebugInfoParser = null
    if(DEBUG_FLOW)
      println("Flow: about to initialize reg trace")
    if(dexMethodHeadParser.getDebugOffset != 0L) {
      debugInfoParser = parseDebugInfoBlock(dexMethodHeadParser )
    }
    instructionParser.setFilePosition(dexMethodHeadParser.getInstructionBase)
    instructionParser.setPass(false)
    instructionParser.setRegisterMap(initRegMap.toMap)
    instructionParser.setLocalVars(localvars.toMap)
    breakable{ // 1
      do {
        var filePos: Long = instructionParser.getFilePosition
        if(DEBUG_FLOW)
          println("Flow: about to enter block parsing, file pos: 0x" + java.lang.Long.toHexString(filePos))
        breakable { // 2
          while(filePos < endPos) {
            filePos = instructionParser.getFilePosition
            if(DEBUG_FLOW)
              println("Flow: block parsing, file pos: 0x" + java.lang.Long.toHexString(filePos))
            if(DEBUG_REGTRACE)
              println("regTrace: 0x" + java.lang.Long.toHexString(filePos) + "; regMap: [" + 
                  instructionParser.getRegisterMap + "]")
            val basePos: Int = (filePos - startPos).asInstanceOf[Int]
            // Continue here or not? The rules are:
            // - If we have not been here yet, continue
            // - If we have been here but there is no saved register map here, continue.
            // - If we have been here and there is saved register map but the overrun counter exceeds the limit, break
            //   the analysis 
            // - Otherwise if the register consistency check indicates that we should continue, do it.
            // - Otherwise break the analysis of the flow.
            val haveBeenHere: Boolean = visitSet.get(basePos)
            
            if(haveBeenHere) {
              val posObj: Long = filePos
              val savedUndeterminedRegMap = registerMaps.getOrElseUpdate(posObj, mmapEmpty)
              if(DEBUG_REGMAPS)
                println("regMaps: 0x" + java.lang.Long.toHexString(filePos) + 
                    "; haveBeenHere: 0x" + java.lang.Long.toHexString(filePos) +
                    "; regmap: [" + savedUndeterminedRegMap + "]")
              val currentUndeterminedRegMap: IMap[Int, DedexUndeterminedType] = instructionParser.getRegisterMap.filter{
                case (reg, typ) => typ.isInstanceOf[DedexUndeterminedType]
              }.map{case (reg, ut) => (reg, ut.asInstanceOf[DedexUndeterminedType])}
              // No undetermined reg, stop.
              if(!currentUndeterminedRegMap.exists(!_._2.mergepos.contains(posObj))) {
                break
              } else {
                if(DEBUG_REGMAPS)
                  println("regMaps: currentUndeterminedRegMap: [" + currentUndeterminedRegMap + "]")
                if(!mergeCheckRegTraceMaps(posObj, currentUndeterminedRegMap, savedUndeterminedRegMap)) {
                  if(DEBUG_REGMAPS)
                    println("regMaps: break")
                  break
                }
                if(DEBUG_REGMAPS)
                  println("regMaps: update")
              }
            }
            // Check if an exception block is starting here. If so, save the register maps for the handler(s)
            // Also, if there is a saved register map for this location, restore the register map from the
            // saved version
            if(DEBUG_FLOW)
              println("Flow: handleRegMaps, file pos: 0x" + java.lang.Long.toHexString(filePos))
            handleRegMaps(exceptionHandlerEntryPointList.toList, instructionParser)
            // Insert debug variables into the register set to handle the case when
            // the debug variable goes into scope ...
            if(DEBUG_FLOW)
              println("Flow: before parse")
            try {
              instructionParser.doparse(startPos, endPos)
            } catch {
              case ex: Exception =>
                if(DEBUG_FLOW)
                  println("Flow: hit unknown instruction")
                break
            }
            if(DEBUG_FLOW)
              println("Flow: after parse")
  
            // Mark that we have visited this place
            val instructionEndPos: Int = (instructionParser.getFilePosition - startPos).asInstanceOf[Int]
            visitSet.set(basePos, instructionEndPos)
  
            // Determine, where to continue the tracing
            val forkStatus = instructionParser.getForkStatus
            if(DEBUG_FLOW)
              println("Flow: forkStatus: " + forkStatus)
            if(forkStatus == ForkStatus.TERMINATE)
              break
            if((forkStatus == DexInstructionToPilarParser.ForkStatus.FORK_UNCONDITIONALLY) ||
                (forkStatus == DexInstructionToPilarParser.ForkStatus.FORK_AND_CONTINUE)) {
              val baseIndex: Int =
                if(forkStatus == DexInstructionToPilarParser.ForkStatus.FORK_UNCONDITIONALLY) 1
                else 0
              val forkData: IList[Long] = instructionParser.getForkData
              // we go to forkData[0], push the rest of the addresses to the visit stack
              for(i <- baseIndex until forkData.length) {
                val target = forkData(i)
                if(DEBUG_FLOW)
                  println("Flow: processing forkData[" + forkData.indexOf(target) + "]: target: 0x" + java.lang.Long.toHexString(target))
                if((target >= startPos) && (target <= endPos)) {
                  val currentRegMap: IMap[Int, DedexType] = instructionParser.getRegisterMap
                  visitStack.push(VisitStackEntry(target, currentRegMap, None))
                }
              }
              if(forkStatus == DexInstructionToPilarParser.ForkStatus.FORK_UNCONDITIONALLY)
                instructionParser.setFilePosition(forkData.head)
            }
          }
        } // breakable2
        if(DEBUG_FLOW)
          println("Flow: block parsing exit 0x" + java.lang.Long.toHexString(filePos))
        // Branch ended (either by reaching end of method or hitting a previously visited instruction)
        // Pull a new address from the stack or finish if the stack is empty
        if(visitStack.empty()) {
          if(DEBUG_FLOW)
            println("Flow: visit stack empty")
          break
        }
        val entry = visitStack.pop()
        val target: Long = entry.location
//        val targetObj = target
        instructionParser.setRegisterMap(entry.regMap)
        // If this is an exception handler entry point, we should have a saved
        // register map for it.
        if(DEBUG_EXCP)
          println("/pop: 0x" + java.lang.Long.toHexString(target) + " ; regmap: " +
              dumpRegMap(instructionParser.getRegisterMap))
        if(DEBUG_FLOW)
          println("Flow: iteration, target address: " + java.lang.Long.toHexString(target))
        instructionParser.setFilePosition(target)
      } while(true)
    } // breakable1
    // Run the post-first pass processing
    instructionParser.postPassProcessing(false)
    // Second pass: generate the code
    instructionParser.setFilePosition(dexMethodHeadParser.getInstructionBase)
    instructionParser.setPass(true)
    instructionParser.setRegisterMap(initRegMap.toMap)
    var actualPosition: Long = instructionParser.getFilePosition
    while(actualPosition < endPos) {
      if(DEBUG_FLOW)
        println("Code generation, file pos: 0x" + java.lang.Long.toHexString(actualPosition))
      var task = instructionParser.getTaskForAddress(actualPosition)
      var parseFlag = false
      if(task.isDefined) {
        try {
          val code = task.get.renderTask(actualPosition)
          codes ++= code
          parseFlag = task.get.getParseFlag(actualPosition)
        } catch {
          case ex: IOException =>
            System.err.println("*** ERROR ***: " + ex.getMessage)
        }
      }
      if(!parseFlag) {
        // Let's check whether the first pass visited this region. If not, turn it into data block
        var visitOffset: Int = (actualPosition - startPos).asInstanceOf[Int]
        if(visitSet.get(visitOffset)) {
          val code = instructionParser.doparse(startPos, endPos)
          codes ++= code
        } else {
          if(dump.isDefined)
            dump.get.println("L%06x".format(instructionParser.getFilePosition))

          actualPosition = instructionParser.getFilePosition
          breakable{ // 3
            while((actualPosition < endPos) && !visitSet.get(visitOffset)) {
              task = instructionParser.getTaskForAddress(actualPosition)
              if(task.isDefined) {
                try {
                  val code = task.get.renderTask(actualPosition)
                  codes ++= code
                  parseFlag = task.get.getParseFlag(actualPosition)
                } catch {
                  case ex: IOException =>
                    System.err.println("*** ERROR ***: " + ex.getMessage)
                } finally {
                  if(actualPosition == instructionParser.getFilePosition) {
                    instructionParser.read8Bit()
                  }
                }
              } else {
                instructionParser.read8Bit()
              }
              actualPosition = instructionParser.getFilePosition
              visitOffset = (actualPosition - startPos).asInstanceOf[Int]
            }
          } // breakable 3
        }
      }
      actualPosition = instructionParser.getFilePosition
    }
    // Run any task that may be at the end of the method (mostly labels)
    val task = instructionParser.getTaskForAddress(endPos)
    if(task.isDefined) {
      try {
        codes ++= task.get.renderTask(endPos)
      } catch {
        case ex: IOException =>
          System.err.println("*** ERROR ***: " + ex.getMessage)
      }
    }
    // Run the post-second pass processing
    instructionParser.postPassProcessing(true)
    localvars ++= instructionParser.getLocalVars
    bodyTemplate.add("codeFragments", codes)
    (bodyTemplate, catchsTemplate)
  }
  
  private def getFieldType(fieldWithType: String): JawaType = {
    val fieldTypStr = fieldWithType.split(" ").last
    JavaKnowledge.formatSignatureToType(fieldTypStr)
  }
  
  private def getReturnType(methodStr: String): JawaType = {
    val retTypStr = methodStr.substring(methodStr.lastIndexOf(")") + 1)
    JavaKnowledge.formatSignatureToType(retTypStr)
  }
 

  def writeTryCatchBlock(catchTemplate: ST, startLabel: String, endLabel: String, exception: JawaType, handlerLabel: String): ST = {
    catchTemplate.add("catchTyp", generateType(exception))
    catchTemplate.add("fromLoc", startLabel)
    catchTemplate.add("toLoc", endLabel)
    catchTemplate.add("targetLoc", handlerLabel)
    catchTemplate
  }
  
  
//  private def printThrows(
//      ps: PrintStream,
//      dap: DexAnnotationParser,
//      annotationIdx: Int,
//      throwsIdx: Int) = {
//    val elementsSize: Int = dap.getAnnotationElementsSize(DexAnnotationParser.AnnotationType.METHOD, annotationIdx, throwsIdx)
//    // In reality, there is only one "value" element. The loop is a pure paranoia
//    for(i <- 0 until elementsSize) {
//      val elementName = dap.getAnnotationElementName(DexAnnotationParser.AnnotationType.METHOD, annotationIdx, throwsIdx, i)
//      if( "value".equals( elementName ) ) {
//        val o = dap.getAnnotationElementValue(DexAnnotationParser.AnnotationType.METHOD, annotationIdx, throwsIdx, i)
//        o match {
//          case array: StaticArray =>
//            for(n <- 0 until array.length)
//                ps.println(".throws " + array.get(n))
//          case _ =>
//        }
//      }
//    }
//  }
  
//  private def printElements(
//      ps: PrintStream,
//      dap: DexAnnotationParser,
//      typ: DexAnnotationParser.AnnotationType,
//      annotationIdx: Int,
//      n: Int) = {
//    for(k <- 0 until dap.getAnnotationElementsSize(typ, annotationIdx, n)) {
//      val parmName = dap.getAnnotationElementName(typ, annotationIdx, n, k)
//      val o = dap.getAnnotationElementValue(typ, annotationIdx,n,k )
//      ps.println("    " + parmName + " " + DexEncodedArrayParser.getTypeString( o ) + " = " + o.toString)
//    }
//  }
  
  // Visit stack entry. Stores the location to return to and the register map at that location
  case class VisitStackEntry(location: Long, regMap: IMap[Int, DedexType], updateLocation: Option[Long]) {
    override def toString: String = {
      val b = new StringBuilder()
      b.append("VisitStackEntry: 0x" + java.lang.Long.toHexString(location))
      b.append(" {")
      b.append(dumpRegMap(regMap))
      b.append("}")
      b.toString.intern()
    }
  }

  case class ExceptionHandlerMapEntry(start: Long,
      end: Long,
      handler: Long,
      exceptionType: JawaType,
      regMap: MMap[Int, DedexType]) {

    def withinRange(pos: Long): Boolean = {
      (pos >= start) && (pos < end)
    }

    def atHandler(pos: Long): Boolean = {
      pos == handler
    }

    override def toString: String = {
      "ExceptionHandlerMapEntry: start: 0x" +
      java.lang.Long.toHexString(start) + "; end: 0x" + 
      java.lang.Long.toHexString(end) + "; handler: " +
      java.lang.Long.toHexString(handler) +
      "; exceptionType: " + exceptionType
    }
  }
  
  private def dumpRegMap(regMap: IMap[Int, DedexType]): StringBuilder = {
    val b = new StringBuilder()
    regMap foreach{
      case (i, value) =>
        b.append(" v" + i + ": " + value)
    }
    b
  }

  /**
    * Check if there was an overrun at a certain location. 
    * The register analyser may fall into endless loop if the regmap
    * solution does not converge. We use an arbitrary limit of 5 iterations and
    * interrupt the analyser if a certain location is visited too many times.
    * Returns true if there is no overrun, false otherwise
    */
//  private def overrunCheck(posObj: Long, overrunCounter: MMap[Long, Integer]): Boolean = {
//    var ctr = overrunCounter.get(posObj)
//    if(!ctr.isDefined) {
//      ctr = Some(new Integer(1))
//      overrunCounter.put(posObj, ctr.get)
//      return true
//    }
//    val ctrv = ctr.get.intValue() + 1
//    if(ctrv > REVISIT_LIMIT)
//      return false
//    overrunCounter.put(posObj, new Integer(ctrv))
//    true
//  }
  
  private def processTryCatchBlock(
      procName: String,
      catchsTemplate: ST,
      instructionParser: DexInstructionToPilarParser,
      dexMethodHeadParser: DexMethodHeadParser,
      visitStack: util.Stack[VisitStackEntry],
      initRegMap: MMap[Int, DedexType],
      exceptionHandlerList: MList[ExceptionHandlerMapEntry]) = {
    val dtcb = new DexTryCatchBlockParser()
    dtcb.setDexMethodHeadParser(dexMethodHeadParser)
    dtcb.setDexTypeIdsBlock(dexTypeIdsBlock)
    dtcb.setDumpFile(dump.orNull)
    dtcb.setRandomAccessFile(file)
    dtcb.parse()
    val catchs: util.ArrayList[ST] = new util.ArrayList[ST]
    for(i <- dtcb.getTriesSize - 1 to 0 by - 1) {
      val start: Long = dtcb.getTryStartOffset(i)
      val end: Long = dtcb.getTryEndOffset(i)
      val startLabel: String = "Try_start" + i
      val endLabel: String = "Try_end" + i
      instructionParser.placeTask(start, LabelTask(startLabel, instructionParser, 0))
      instructionParser.placeTask(end, LabelTask(endLabel, instructionParser, 1))
      for(n <- 0 until dtcb.getTryHandlersSize(i)) {
        val catchTemplate: ST = template.getInstanceOf("Catch")
        val excpT: String = "L" + dtcb.getTryHandlerType(i, n) + ";"
        val excpType: JawaType = JavaKnowledge.formatSignatureToType(excpT)
        val handlerOffset: Long = dtcb.getTryHandlerOffset(i, n)
        visitStack.push(VisitStackEntry(handlerOffset, initRegMap.toMap, Some(start)))
        val handlerLabel = "L%06x".format(handlerOffset)
        // Put a marker for the first pass that register map needs to be saved for a certain
        // exception handler at the start location
        saveExceptionHandlerMapMarker(procName, exceptionHandlerList, start, end, handlerOffset, excpType, initRegMap)
        writeTryCatchBlock(catchTemplate, startLabel, endLabel, excpType, handlerLabel)
        catchs.add(0, catchTemplate)
      }
    }
    catchsTemplate.add("catchs", catchs)
  }
  
  private def saveExceptionHandlerMapMarker(
      procName: String,
      exceptionHandlerList: MList[ExceptionHandlerMapEntry],
      start: Long,
      end: Long,
      handlerOffset: Long,
      exceptionType: JawaType,
      regMap: MMap[Int, DedexType]) = {
    val entry = ExceptionHandlerMapEntry(start, end, handlerOffset, exceptionType, regMap)
    exceptionHandlerList.add(entry)
    if(DEBUG_EXCP)
      println("excp,saveMarker: " + procName + "; entry: " + entry)
  }
  
  private def parseDebugInfoBlock(
      dexMethodHeadParser: DexMethodHeadParser): DexDebugInfoParser = {
    val ddp = new DexDebugInfoParser()
    ddp.setDexStringIdsBlock(dexStringIdsBlock)
    ddp.setDexTypeIdsBlock(dexTypeIdsBlock)
    ddp.setDumpFile(dump.orNull)
    ddp.setRandomAccessFile(file)
    ddp.setFilePosition(dexMethodHeadParser.getDebugOffset)
    ddp.parse()
    ddp
  }
  
  /**
   * Merges the current register map with the register map associated to the
   * exception handler.
   * Rules:
   * - If the current map contains a register with a certain number but the
   *   exception handler map does not contain it, add the register and its value
   *   to the exception handler map.
   * - If the exception handler map contains a register with single-length value
   *   but the current map contains it with an object value, write over the exception
   *   handler map with the value in the current map.
   * Otherwise there is no change.
   */
  private def mergeExcpRegMaps(
      exceptionMap: MMap[Int, DedexType],
      currentMap: IMap[Int, DedexType]) = {
    currentMap foreach {
      case (key, currentValue) =>
        val excpValue = exceptionMap.getOrElse(key, null)
        if(excpValue == null) {
          exceptionMap.put(key, currentValue)
        } else if(currentValue != null){
          exceptionMap.put(key, currentValue)
        }
    }
  }

  private def mergeCheckRegTraceMaps(
      pos: Long,
      newUndeterminedRegTraceMap: IMap[Int, DedexUndeterminedType],
      savedUndeterminedRegTraceMap: MMap[Int, MSet[DedexUndeterminedType]]): Boolean = {
    var revisit = false
    newUndeterminedRegTraceMap foreach {
      case (reg, ud) =>
        ud.mergepos += pos
        val saved = savedUndeterminedRegTraceMap.getOrElseUpdate(reg, msetEmpty)
        if(!saved.contains(ud)){
          saved += ud
          revisit = true
        }
    }
    revisit
  }
  
  private def handleRegMaps(
      exceptionHandlerEntryPointList: IList[ExceptionHandlerMapEntry],
      instructionParser: DexInstructionToPilarParser) = {
    val pos: Long = instructionParser.getFilePosition
    // Iterate over the handlers and figure out the current position is in the range
    // of any active exception handlers. If so, merge the current register map into
    // the register map belonging to the exception handler. If the current position
    // is the handler address of the exception, activate the saved register map
    // belonging to the exception
    for(i <- exceptionHandlerEntryPointList.indices) {
      val entry: ExceptionHandlerMapEntry = exceptionHandlerEntryPointList(i)
      if(entry.withinRange(pos)) {
        if(DEBUG_EXCP)
          println("excp,withinRange: " + java.lang.Long.toHexString(pos) + ": " + entry)
        val regMap = instructionParser.getRegisterMap
        mergeExcpRegMaps(entry.regMap, regMap)
        if(DEBUG_EXCP)
          println("excp,merged regmap: 0x" + java.lang.Long.toHexString(pos) + "; entry: " +
              entry + "; merged regmap: " + entry.regMap)
      }
      if(entry.atHandler(pos)) {
        val excpRegMap = entry.regMap
        // We can't set the original instance to instruction parser - that would
        // corrupt the register map for further executions of the handler.
        excpRegMap.put(DexInstructionParser.REGMAP_RESULT_KEY, DedexJawaType(entry.exceptionType))
        if(DEBUG_EXCP)
          println("excp,setRegMap: 0x" + java.lang.Long.toHexString( pos ) + 
              "; exception register map set: [" + excpRegMap+ "]")
        instructionParser.setRegisterMap(excpRegMap.toMap)
      }
    }
  }
  
  def writeByteArray(element: String) = {
    if(dump.isDefined)
      dump.get.println("\t\t" + element)
  }
  
  // the input will look like:
  //   public synchronized com/android/commands/input/Input 
  //   public booleanArray()V
  // Output should be:
  //   PUBLIC_SYNCHRONIZED
  //   PUBLIC
  private def getAccessString(name: String, skip: Int, isInterface: Boolean, isConstructor: Boolean): String = {
    val strs = name.split(" ")
    var acc: String =
      if(strs.size <= skip) ""
      else {
        val b = new StringBuilder
        for(i <- 0 to strs.size - (1 + skip)) b.append(strs(i) + " ")
        val accessStr = b.toString.trim
        accessStringToPilarString(accessStr)
      }
    if(isInterface){
      if(acc.isEmpty) acc += "INTERFACE"
      else acc += "_INTERFACE"
    }
    if(isConstructor) {
      if(acc.isEmpty) acc += "CONSTRUCTOR"
      else acc += "_CONSTRUCTOR"
    }
    acc
  }
  
  private def accessStringToPilarString(accessStr: String): String = {
    accessStr.toUpperCase().replaceAll(" ", "_")
  }
  
  private def toPilarRecordName(str: String): String = {
    str.replaceAll("/", ".")
  }
}
