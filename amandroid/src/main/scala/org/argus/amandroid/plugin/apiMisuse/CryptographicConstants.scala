/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin.apiMisuse

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object CryptographicConstants {
  final val JAVAX_CIPHER_GETINSTANCE_1 = "Ljavax/crypto/Cipher;.getInstance:(Ljava/lang/String;)Ljavax/crypto/Cipher;"
  final val JAVAX_CIPHER_GETINSTANCE_2 = "Ljavax/crypto/Cipher;.getInstance:(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/Cipher;"

	final val JAVAX_IVPARAMETER_INIT_1 = "Ljavax/crypto/spec/IvParameterSpec;.<init>:([B)V"
	final val JAVAX_IVPARAMETER_INIT_2 = "Ljavax/crypto/spec/IvParameterSpec;.<init>:([BII)V"

  def getCryptoAPIs: Set[String] = getCipherGetinstanceAPIs ++ getIVParameterInitAPIs
  def getCipherGetinstanceAPIs: Set[String] = Set(JAVAX_CIPHER_GETINSTANCE_1, JAVAX_CIPHER_GETINSTANCE_2)
	def getIVParameterInitAPIs: Set[String] = Set(JAVAX_IVPARAMETER_INIT_1, JAVAX_IVPARAMETER_INIT_2)
  
  final val AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5Padding"
	final val AES = "AES" //*
	final val DES_ECB_NOPADDING = "DES/ECB/NoPadding"
	final val DES = "DES" //*
	final val DESEDE = "DESede" //*
	final val DESESE_ECB_PKCS5PADDING = "DESede/ECB/PKCS5Padding"
	final val AES_CBC_NOPADDING = "AES/CBC/NoPadding"
	final val AES_ECB_PKCS5PADDING = "AES/ECB/PKCS5Padding"
	final val AES_CBC_PKCS7PADDING = "AES/CBC/PKCS7Padding"
	final val DES_ECB_PKCS5PADDING = "DES/ECB/PKCS5Padding"
	final val AES_ECB_NOPADDING = "AES/ECB/NoPadding"
	final val DES_CBC_PKCS5PADDING = "DES/CBC/PKCS5Padding"
	final val AES_ECB_PKCS7PADDING = "AES/ECB/PKCS7Padding"
	final val AES_CFB8_NOPADDING = "AES/CFB8/NoPadding"
  
	def getSymmetricEncryptionSchemes: Set[String] = Set(
	  AES_CBC_PKCS5PADDING, AES, DES_ECB_NOPADDING, DES, DESEDE, DESESE_ECB_PKCS5PADDING,
	  AES_CBC_NOPADDING, AES_ECB_PKCS5PADDING, AES_CBC_PKCS7PADDING, DES_ECB_PKCS5PADDING,
	  AES_ECB_NOPADDING, DES_CBC_PKCS5PADDING, AES_ECB_PKCS7PADDING, AES_CFB8_NOPADDING
	)
	
	def getECBSchemes: Set[String] = Set(
	  AES, DES_ECB_NOPADDING, DES, DESEDE, DESESE_ECB_PKCS5PADDING, AES_ECB_PKCS5PADDING, 
	  DES_ECB_PKCS5PADDING, AES_ECB_NOPADDING, AES_ECB_PKCS7PADDING
	)
}
