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

import org.argus.jawa.core.util._
import java.io.FileInputStream
import java.util.jar.JarFile

import collection.JavaConverters._
import java.security.cert.X509Certificate
import java.io.InputStream
import java.security.cert.CertificateFactory
import java.util.Date
import java.security.cert.Certificate
import java.security.MessageDigest
import java.security.interfaces.RSAPublicKey

import org.argus.amandroid.core.ApkGlobal

case class ApkCertificate(
    typ: String,
    version: Int,
    serialNumber: BigInt,
    owner: String,
    issuer: String,
    validity: ApkCertificateValidity,
    pubkey: ApkPublicKey,
    certSig: ApkCertificateSignature,
    fps: ApkCertificateFingerprints
    ) {
  override def toString: String = {
    val sb: StringBuilder = new StringBuilder
    sb.append("Type: " + typ + "\n")
    sb.append("Version: " + version + "\n")
    sb.append("Serial number: " + serialNumber.longValue().toHexString + "\n")
    sb.append("Owner:  " + owner + "\n")
    sb.append("Issuer: " + issuer + "\n")
    sb.append(validity.toString)
    sb.append(pubkey.toString)
    sb.append(certSig.toString)
    sb.append(fps.toString)
    sb.toString()
  }
}

case class ApkCertificateValidity(notBefore: Date, notAfter: Date) {
  override def toString: String = {
    val sb: StringBuilder = new StringBuilder
    sb.append("Validity:\n")
    sb.append("\tfrom: " + notBefore + "\n")
    sb.append("\t  to: " + notAfter + "\n")
    sb.toString
  }
}

case class ApkCertificateFingerprints(md5fp: String, sha1fp: String, sha256fp: String) {
  override def toString: String = {
    val sb: StringBuilder = new StringBuilder
    sb.append("Certificate fingerprints:\n")
    sb.append("\tMD5: " + md5fp + "\n")
    sb.append("\tSHA1: " + sha1fp + "\n")
    sb.append("\tSHA256: " + sha256fp + "\n")
    sb.toString()
  }
}

case class ApkCertificateSignature(algName: String, oid: String, hexdata: String) {
  override def toString: String = {
    val sb: StringBuilder = new StringBuilder
    sb.append("Signature:\n")
    sb.append("\ttype: " + algName + "\n")
    sb.append("\tOID: " + oid + "\n")
    sb.append("\thexdata: " + hexdata + "\n")
    sb.toString
  }
}

case class ApkPublicKey(algName: String, exponent: BigInt, modulus: BigInt) {
  override def toString: String = {
    val sb: StringBuilder = new StringBuilder
    sb.append("Public Key:\n")
    sb.append("\ttype: " + algName + " " + modulus.bitLength + " bits" + "\n")
    sb.append("\texponent: " + exponent + "\n")
    sb.append("\thexdata: " + modulus + "\n")
    sb.toString
  }
}

object ApkCertificateReader {
  
  private def DEBUG = false
  
  def apply(fileUri: FileResourceUri): ISet[ApkCertificate] = {
    val apkcerts: MSet[ApkCertificate] = msetEmpty
    if(ApkGlobal.isValidApk(fileUri)) {
      val jf = new JarFile(FileUtil.toFile(fileUri), true)
      for(ent <- jf.entries().asScala) {
        if(ent.getName.startsWith("META-INF/") && ent.getName.endsWith(".RSA")) {
          val is = jf.getInputStream(ent)
          apkcerts ++= getCertFromStream(is)
        }
      }
    } else {
      val file = FileUtil.toFile(fileUri)
      val is = new FileInputStream(file)
      apkcerts ++= getCertFromStream(is)
    }
    apkcerts.toSet
  }
  
  private def getCertFromStream(is: InputStream): ISet[ApkCertificate] = {
    val apkcerts: MSet[ApkCertificate] = msetEmpty
    val cf = CertificateFactory.getInstance("X509")
    try {
      val c = cf.generateCertificates(is)
      c.asScala.foreach { cert =>
        val x509cert = cert.asInstanceOf[X509Certificate]
        val md5fp = getCertFingerPrint("MD5", cert)
        val sha1fp = getCertFingerPrint("SHA1", cert)
        val sha256fp = getCertFingerPrint("SHA-256", cert)
        val rsaPubKey = x509cert.getPublicKey.asInstanceOf[RSAPublicKey]
        val validity = ApkCertificateValidity(x509cert.getNotBefore, x509cert.getNotAfter)
        val pubKey = ApkPublicKey(rsaPubKey.getAlgorithm, rsaPubKey.getPublicExponent, rsaPubKey.getModulus)
        val certSig = ApkCertificateSignature(x509cert.getSigAlgName, x509cert.getSigAlgOID, toHexString(x509cert.getSignature))
        val fps = ApkCertificateFingerprints(md5fp, sha1fp, sha256fp)
        apkcerts += ApkCertificate(
            x509cert.getType,
            x509cert.getVersion,
            x509cert.getSerialNumber,
            x509cert.getSubjectDN.getName,
            x509cert.getIssuerDN.getName,
            validity,
            pubKey,
            certSig,
            fps)
      }
    } catch {
      case e: Exception =>
        if(DEBUG)
          e.printStackTrace()
    }
    apkcerts.toSet
  }
  
  private def getCertFingerPrint(mdAlg: String, cert: Certificate): String = {
    val encCertInfo = cert.getEncoded
    val md = MessageDigest.getInstance(mdAlg)
    val digest = md.digest(encCertInfo)
    toHexString(digest)
  }
  
  private def toHexString(block: Array[Byte]): String = {
    val buf = new StringBuffer()
    val len = block.length
    for (i <- 0 until len) {
      byte2hex(block(i), buf)
      if (i < len-1) {
        buf.append(":")
      }
    }
    buf.toString
  }
  
  private def byte2hex(b: Byte, buf: StringBuffer) = {
    val hexChars = Array(
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    )
    val high = (b & 0xf0) >> 4
    val low = b & 0x0f
    buf.append(hexChars(high))
    buf.append(hexChars(low))
  }
}