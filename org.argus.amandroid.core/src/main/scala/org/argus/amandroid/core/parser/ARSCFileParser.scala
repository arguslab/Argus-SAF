/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.parser

import java.io.InputStream
import java.io.IOException
import org.sireum.util._
import java.io.File
import java.net.URI

/**
 * Parser for reading out the contents of Android's resource.arsc file.
 * Structure declarations and comments taken from the Android source
 * code and ported from java to scala.
 * 
 * adapted from Steven Arzt
 * 
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */
class ARSCFileParser {
	final val TITLE = "ARSCFileParser"
//	private final val DEBUG = false

	protected final val RES_STRING_POOL_TYPE = 0x0001
	protected final val RES_TABLE_TYPE = 0x0002
	protected final val RES_TABLE_PACKAGE_TYPE = 0x0200
	protected final val RES_TABLE_TYPE_SPEC_TYPE = 0x0202
	protected final val RES_TABLE_TYPE_TYPE = 0x0201
	
	protected final val SORTED_FLAG = 1<<0
	protected final val UTF8_FLAG = 1<<8
	
	protected final val SPEC_PUBLIC = 0x40000000
	
	/**
	 * Contains no data
	 */
	protected final val TYPE_NULL = 0x00
	/**
	 * The 'data' holds a ResTable_ref, a reference to another resource table
	 * entry.
	 */
	protected final val TYPE_REFERENCE = 0x01
    /**
     * The 'data' holds an attribute resource identifier.
     */
	protected final val TYPE_ATTRIBUTE = 0x02
    /**
     * The 'data' holds an index into the containing resource table's global
     * value string pool.
     */
	protected final val TYPE_STRING = 0x03
    /**
     * The 'data' holds a single-precision floating point number.
     */
	protected final val TYPE_FLOAT = 0x04
    /**
     * The 'data' holds a complex number encoding a dimension value, such as
     * "100in".
     */
	protected final val TYPE_DIMENSION = 0x05
    /**
     * The 'data' holds a complex number encoding a fraction of a container.
     */
	protected final val TYPE_FRACTION = 0x06
    /**
     * Beginning of integer flavors...
     */
	protected final val TYPE_FIRST_INT = 0x10
    /**
     * The 'data' is a raw integer value of the form n..n.
     */
	protected final val TYPE_INT_DEC = 0x10
    /**
     * The 'data' is a raw integer value of the form 0xn..n.
     */
	protected final val TYPE_INT_HEX = 0x11
    /**
     * The 'data' is either 0 or 1, for input "false" or "true" respectively.
     */
	protected final val TYPE_INT_BOOLEAN = 0x12
    /**
     * Beginning of color integer flavors...
     */
	protected final val TYPE_FIRST_COLOR_INT = 0x1c
    /**
     * The 'data' is a raw integer value of the form #aarrggbb.
     */
	protected final val TYPE_INT_COLOR_ARGB8 = 0x1c
    /**
     * The 'data' is a raw integer value of the form #rrggbb.
     */
	protected final val TYPE_INT_COLOR_RGB8 = 0x1d
    /**
     * The 'data' is a raw integer value of the form #argb.
     */
	protected final val TYPE_INT_COLOR_ARGB4 = 0x1e
    /**
     * The 'data' is a raw integer value of the form #rgb.
     */
	protected final val TYPE_INT_COLOR_RGB4 = 0x1f
    /**
     * ...end of integer flavors.
     */
	protected final val TYPE_LAST_COLOR_INT = 0x1f
    /**
     * ...end of integer flavors.
     */
	protected final val TYPE_LAST_INT = 0x1f
	
    /**
     * This entry holds the attribute's type code.
     */
	protected final val ATTR_TYPE = 0x01000000 | (0 & 0xFFFF)
	/**
	 * For integral attributes, this is the minimum value it can hold.
	 */
	protected final val ATTR_MIN = 0x01000000 | (1 & 0xFFFF)
    /**
     * For integral attributes, this is the maximum value it can hold.
     */
	protected final val ATTR_MAX = 0x01000000 | (2 & 0xFFFF)
    /**
     * Localization of this resource is can be encouraged or required with
     * an aapt flag if this is set
     */
	protected final val ATTR_L10N = 0x01000000 | (3 & 0xFFFF)

    // for plural support, see android.content.res.PluralRules#attrForQuantity(int)
	protected final val ATTR_OTHER = 0x01000000 | (4 & 0xFFFF)
	protected final val ATTR_ZERO = 0x01000000 | (5 & 0xFFFF)
	protected final val ATTR_ONE = 0x01000000 | (6 & 0xFFFF)
	protected final val ATTR_TWO = 0x01000000 | (7 & 0xFFFF)
	protected final val ATTR_FEW = 0x01000000 | (8 & 0xFFFF)
	protected final val ATTR_MANY = 0x01000000 | (9 & 0xFFFF)

    protected final val NO_ENTRY = 0xFFFFFFFF
    
    /**
     * Where the unit type information is.  This gives us 16 possible types, as
     * defined below.
     */
    protected final val COMPLEX_UNIT_SHIFT = 0x0
    protected final val COMPLEX_UNIT_MASK = 0xf    
    /**
     * TYPE_DIMENSION: Value is raw pixels.
     */
    protected final val COMPLEX_UNIT_PX = 0
    /**
     * TYPE_DIMENSION: Value is Device Independent Pixels.
     */
    protected final val COMPLEX_UNIT_DIP = 1
    /**
     * TYPE_DIMENSION: Value is a Scaled device independent Pixels.
     */
    protected final val COMPLEX_UNIT_SP = 2
    /**
     * TYPE_DIMENSION: Value is in points.
     */
    protected final val COMPLEX_UNIT_PT = 3
    /**
     * TYPE_DIMENSION: Value is in inches.
     */
    protected final val COMPLEX_UNIT_IN = 4
    /**
     * TYPE_DIMENSION: Value is in millimeters.
     */
    protected final val COMPLEX_UNIT_MM = 5
	/**
	 * TYPE_FRACTION: A basic fraction of the overall size.
	 */
    protected final val COMPLEX_UNIT_FRACTION = 0
    /**
     * TYPE_FRACTION: A fraction of the parent size.
     */
    protected final val COMPLEX_UNIT_FRACTION_PARENT = 1
	/**
	 * Where the radix information is, telling where the decimal place appears
	 * in the mantissa.  This give us 4 possible fixed point representations as
	 * defined below.
	 */
    protected final val COMPLEX_RADIX_SHIFT = 4
    protected final val COMPLEX_RADIX_MASK = 0x3
    /**
     * The mantissa is an integral number -- i.e., 0xnnnnnn.0
     */
    protected final val COMPLEX_RADIX_23p0 = 0
    /**
     * The mantissa magnitude is 16 bits -- i.e, 0xnnnn.nn
     */
    protected final val COMPLEX_RADIX_16p7 = 1
	/**
	 * The mantissa magnitude is 8 bits -- i.e, 0xnn.nnnn
	 */
    protected final val COMPLEX_RADIX_8p15 = 2
    /**
     * The mantissa magnitude is 0 bits -- i.e, 0x0.nnnnnn
     */
    protected final val COMPLEX_RADIX_0p23 = 3
    /**
     * Where the actual value is.  This gives us 23 bits of precision. The top
     * bit is the sign.
     */
    protected final val COMPLEX_MANTISSA_SHIFT = 8
    protected final val COMPLEX_MANTISSA_MASK = 0xffffff
    
	/**
	 * If set, this is a complex entry, holding a set of name/value mappings.
	 * It is followed by an array of ResTable_Map structures.
	 */
	final val FLAG_COMPLEX = 0x0001
	/**
	 * If set, this resource has been declared public, so libraries are
	 * allowed to reference it.
	 */
	final val FLAG_PUBLIC = 0x0002

	private final var stringTable: Map[Int, String] = Map()
	private final var packages: List[ResPackage] = List()

	class ResPackage {
		var packageId: Int = 0
		var packageName: String = null
		var types: List[ResType] = List()
		
		def getPackageId: Int = this.packageId
		
		def getPackageName: String = this.packageName
		
		def getDeclaredTypes: List[ResType] = this.types
		
		override def toString: String = {
		  val sb = new StringBuilder
		  sb.append("ResPackage(" + "id:" + packageId + ",name:" + packageName + ",types:" + types + ")")
		  sb.toString.intern()
		}
	}
	
	/**
	 * A resource type in an Android resource file. All resources are associated
	 * with a type.
	 */
	class ResType {
		var id: Int = 0
		var typeName: String = null
		var configurations: List[ResConfig] = List()

		def getTypeName: String = this.typeName
		
		def getConfigurations: List[ResConfig] = this.configurations
		
		/**
		 * Gets a list of all resources in this type regardless of the
		 * configuration. Resources sharing the same ID will only be returned
		 * once, taking the value from the first applicable configuration.
		 * @return A list of all resources of this type.
		 */
		def getAllResources: Iterable[AbstractResource] = {
			var resources: Map[String, AbstractResource] = Map()
			for (rc <- this.configurations)
				for (res <- rc.getResources)
					if (!resources.keySet.contains(res.resourceName))
							resources ++= Map(res.resourceName -> res)
			resources.values
		}
		
		/**
		 * Gets the first resource of the current type that has the given name
		 * @param resourceName The resource name to look for
		 * @return The resource with the given name if it exists, otherwise
		 * null
		 */
		def getFirstResource(resourceName: String): AbstractResource = {
			for (rc <- this.configurations)
				for (res <- rc.getResources)
					if (res.resourceName.equals(resourceName))
						return res
			null
		}

		/**
		 * Gets the first resource of the current type with the given ID 
		 * @param resourceID The resource ID to look for
		 * @return The resource with the given ID if it exists, otherwise
		 * null
		 */
		def getFirstResource(resourceID: Int): AbstractResource = {
			for (rc <- this.configurations)
				for (res <- rc.getResources)
					if (res.resourceID == resourceID)
						return res
			null
		}
		
		override def toString: String = {
		  val sb = new StringBuilder
		  sb.append("ResType(" + "id:" + id + ",name:" + typeName + ",configs:" + configurations + ")")
		  sb.toString.intern()
		}
	}
	
	/**
	 * A configuration in an Android resource file. All resources are associated
	 * with a configuration (which may be the default one).
	 */
	class ResConfig {
		var resources: List[AbstractResource] = List()

		def getResources: List[AbstractResource] = this.resources
		
		override def toString: String = {
		  val sb = new StringBuilder
		  sb.append("ResConfig(" + "ress:" + resources + ")")
		  sb.toString.intern()
		}
	}
		
	/**
	 * Abstract base class for all Android resources.
	 */
	sealed abstract class AbstractResource {
		var resourceName: String = null
		var resourceID: Int = 0
		
		def getResourceName: String = this.resourceName
		
		def getResourceID: Int = this.resourceID
		
		override def toString: String = {
		  val sb = new StringBuilder
		  sb.append("AbstractResource(" + "name:" + resourceName + ",id:" + resourceID + ")")
		  sb.toString.intern()
		}
	}
	
	/**
	 * Android resource that does not contain any data
	 */
	case class NullResource() extends AbstractResource {	
	}

	/**
	 * Android resource containing a reference to another resource.
	 */
	case class ReferenceResource(referenceID: Int) extends AbstractResource {
	}

	/**
	 * Android resource containing an attribute resource identifier.
	 */
	case class AttributeResource(attributeID: Int) extends AbstractResource {
	}

	/**
	 * Android resource containing string data.
	 */
	case class StringResource(value: String) extends AbstractResource {
	}

	/**
	 * Android resource containing integer data.
	 */
	case class IntegerResource(value: Int) extends AbstractResource {
	}
	
	/**
	 * Android resource containing a single-precision floating point number
	 */
	case class FloatResource(value: Float) extends AbstractResource {
	}

	/**
	 * Android resource containing boolean data.
	 */
	case class BooleanResource(value: Boolean) extends AbstractResource {
	}
	
	/**
	 * Android resource containing color data.
	 */
	case class ColorResource(a: Int, r: Int, g: Int, b: Int) extends AbstractResource {
	}
	
	/**
	 * Enumeration containing all dimension units available in Android
	 */
	object Dimension extends Enumeration {
		val PX, DIP, SP, PT, IN, MM = Value
	}
	
	/**
	 * Android resource containing dimension data like "11pt".
	 */
	case class DimensionResource(var value: Int, var unit: Dimension.Value) extends AbstractResource {
		def this(dimension: Int, value: Int) = this(value,
		    {
					dimension match {
					case COMPLEX_UNIT_PX =>
						Dimension.PX
					case COMPLEX_UNIT_DIP =>
						Dimension.DIP
					case COMPLEX_UNIT_SP =>
						Dimension.SP
					case COMPLEX_UNIT_PT =>
						Dimension.PT
					case COMPLEX_UNIT_IN =>
						Dimension.IN
					case COMPLEX_UNIT_MM =>
						Dimension.MM
					case _ =>
						throw new RuntimeException("Invalid dimension: " + dimension)
					}
				})
		
		def getUnit: Dimension.Value = this.unit
	}
	
	/**
	 * Android resource containing complex map data.
	 */
	case class ComplexResource(value: MMap[String, AbstractResource]) extends AbstractResource {
	}

	protected class ResTable_Header {
		val header = new ResChunk_Header()
		/**
		 * The number of ResTable_package structures
		 */
		var packageCount: Int = 0	// uint32
	}
	
	/**
	 * Header that appears at the front of every data chunk in a resource
	 */
	protected class ResChunk_Header {
		/**
		 * Type identifier of this chunk. The meaning of this value depends on
		 * the containing class.
		 */
		var typ: Int	= 0		// uint16
		/**
		 * Size of the chunk header (in bytes). Adding this value to the address
		 * of the chunk allows you to find the associated data (if any).
		 */
		var headerSize: Int = 0		// uint16
		/**
		 * Total size of this chunk (in bytes). This is the chunkSize plus
		 * the size of any data associated with the chunk. Adding this value
		 * to the chunk allows you to completely skip its contents. If this
		 * value is the same as chunkSize, there is no data associated with
		 * the chunk.
		 */
		var size: Int = 0			// uint32
	}
	
	protected class ResStringPool_Header {
		var header: ResChunk_Header = null
		
		/**
		 * Number of strings in this pool (number of uint32_t indices that follow
		 * in the data).
		 */
		var stringCount: Int	= 0	// uint32
		/**
		 * Number of style span arrays in the pool (number of uint32_t indices
		 * follow the string indices).
		 */
		var styleCount: Int = 0			// uint32
		/**
		 * If set, the string index is sorted by the string values (based on
		 * strcmp16()).
		 */
		var flagsSorted: Boolean = false	// 1<<0
		/**
		 * String pool is encoded in UTF-8.
		 */
		var flagsUTF8: Boolean	= false	// 1<<8
		/**
		 * Index from the header of the string data.
		 */
		var stringsStart: Int = 0		// uint32
		/**
		 * Index from the header of the style data.
		 */
		var stylesStart: Int	= 0	// uint32
	}
	
	protected class ResTable_Package {
		var header: ResChunk_Header = null

		/**
		 * If this is the base package, its ID. Package IDs start at 1
		 * (corresponding to the value of the package bits in a resource
		 * identifier). 0 means that this is not a base package.
		 */
		var id: Int = 0			// uint32
		/**
		 * Actual name of this package, \0-terminated
		 */
		var name: String = null	// char16
		/**
		 * Offset to a ResStringPool_Header defining the resource type symbol
		 * table. If zero, this package is inheriting from another base package
		 * (overriding specific values in it).
		 */
		var typeStrings: Int	= 0	// uint32
		/**
		 * Last index into typeStrings that is for public use by others.
		 */
		var lastPublicType: Int = 0		// uint32
		/**
		 * Offset to a ResStringPool_Header defining the resource key symbol
		 * table. If zero, this package is inheriting from another base package
		 * (overriding specific values in it).
		 */
		var keyStrings: Int	= 0		// uint32
		/**
		 * Last index into keyStrings that is for public use by others.
		 */
		var lastPublicKey: Int	= 0	// uint32
	}
	
	/**
	 * A specification of the resources defined by a particular type.
	 * 
	 * There should be one of these chunks for each resource type.
	 * 
	 * This structure is followed by an array of integers providing the set of
	 * configuration change flags (ResTable_Config::CONFIG_*) that have multiple
	 * resources for that configuration. In addition, the high bit is set if
	 * that resource has been made public.
	 */
	protected class ResTable_TypeSpec {
		var header: ResChunk_Header = null
		
		/**
		 * The type identifier this chunk is holding. Type IDs start at 1
		 * (corresponding to the value of the type bits in a resource
		 * identifier). 0 is invalid.
		 */
		var id: Int = 0			// uint8
		/**
		 * Must be 0.
		 */
		var res0: Int = 0		// uint8
		/**
		 * Must be 1.
		 */
		var res1: Int = 0		// uint16
		/**
		 * Number of uint32_t entry configuration masks that follow.
		 */
		var entryCount: Int = 0	// uint32
	}
	
	/**
	 * A collection of resource entries for a particular resource data type.
	 * Followed by an array of uint32_t defining the resource values, corresponding
	 * to the array of type strings in the ResTable_Package::typeStrings string
	 * block. Each of these hold an index from entriesStart a value of NO_ENTRY
	 * means that entry is not defined.
	 * 
	 * There may be multiple of these chunks for a particular resource type,
	 * supply different configuration variations for the resource values of
	 * that type.
	 *
	 * It would be nice to have an additional ordered index of entries, so
	 * we can do a binary search if trying to find a resource by string name.
	 */
	protected class ResTable_Type {
		var header: ResChunk_Header = null
		
		/**
		 * The type identifier this chunk is holding. Type IDs start at 1
		 * (corresponding to the value of the type bits in a resource
		 * identifier). 0 is invalid.
		 */
		var id: Int = 0			// uint8
		/**
		 * Must be 0.
		 */
		var res0: Int = 0		// uint8
		/**
		 * Must be 1.
		 */
		var res1: Int = 0		// uint16

		/**
		 * Number of uint32_t entry indices that follow.
		 */
		var entryCount: Int = 0			// uint32
		/**
		 * Offset from header where ResTable_Entry data starts.
		 */
		var entriesStart: Int = 0		// uint32
		/**
		 * Configuration this collection of entries is designed for,
		 */
		val config = new ResTable_Config()
	}
	
	/**
	 * Describes a particular resource configuration.
	 */
	protected class ResTable_Config {
		/**
		 * Number of bytes in this structure
		 */
		var size: Int = 0		// uint32
		/**
		 * Mobile country code (from SIM). "0" means any.
		 */
		var mmc: Int = 0		// uint16
		/**
		 * Mobile network code (from SIM). "0" means any.
		 */
		var mnc: Int = 0		// uint16
		/**
		 * \0\0 means "any". Otherwise, en, fr, etc.
		 */
		var language = new Array[Char](2)	// char[2]
		/**
		 * \0\0 means "any". Otherwise, US, CA, etc.
		 */
		var country = new Array[Char](2)	// char[2]
		
		var orientation: Int = 0		// uint8
		var touchscreen: Int = 0		// uint8
		var density: Int = 0			// uint16
		
		var keyboard: Int = 0			// uint8
		var navigation: Int = 0	 		// uint8
		var inputFlags: Int = 0			// uint8
		var inputPad0: Int = 0			// uint8
		
		var screenWidth: Int = 0		// uint16
		var screenHeight: Int = 0		// uint16
		
		var sdkVersion: Int = 0			// uint16
		var minorVersion: Int = 0		// uint16
		
		var screenLayout: Int = 0		// uint8
		var uiMode: Int = 0				// uint8
		var smallestScreenWidthDp: Int = 0	// uint16
		
		var screenWidthDp: Int = 0		// uint16
		var screenHeightDp: Int = 0		// uint16
	}
	
	/**
	 * This is the beginning of information about an entry in the resource table.
	 * It holds the reference to the name of this entry, and is immediately
	 * followed by one of:
	 * 		* A Res_value structure, if FLAG_COMPLEX is -not- set
	 * 		* An array of ResTable_Map structures, if FLAG_COMPLEX is set.
	 * 		  These supply a set of name/value mappings of data.
	 */
	protected class ResTable_Entry {
		/**
		 * Number of bytes in this structure
		 */
		var size: Int = 0		// uint16
		var flagsComplex: Boolean = false
		var flagsPublic: Boolean = false
		/**
		 * Reference into ResTable_Package::KeyStrings identifying this entry.
		 */
		var key: Int = 0
	}
	
	/**
	 * Extended form of a ResTable_Entry for map entries, defining a parent map
	 * resource from which to inherit values. 
	 */
	protected class ResTable_Map_Entry extends ResTable_Entry {
		/**
		 * Resource identifier of the parent mapping, or 0 if there is none. 
		 */
		var parent: Int = 0
		/**
		 * Number of name/value pairs that follow for FLAG_COMPLEX.
		 */
		var count: Int = 0		// uint32
	}
	
	/**
	 * Representation of a value in a resource, supplying type information.
	 */
	protected case class Res_Value() {
		/**
		 * Number of bytes in this structure.
		 */
		var size: Int = 0		// uint16
		
		/**
		 * Always set to 0.
		 */
		var	res0: Int = 0		// uint8
		
		var dataType: Int = 0		// uint8
		/**
		 * The data for this type, as interpreted according to dataType.
		 */
		var data: Int = 0			// uint16
	}
	
	/**
	 * A single name/value mapping that is part of a complex resource entry.
	 */
	protected class ResTable_Map {
		/**
		 * The resource identifier defining this mapping's name. For attribute
		 * resources, 'name' can be one of the following special resource types
		 * to supply meta-data about the attribute; for all other resource types
		 * it must be an attribute resource.
		 */
		var name: Int = 0				// uint32
		
		/**
		 * This mapping's value.
		 */
		val value: Res_Value = new Res_Value()
	}

	/**
	 * Class containing the data encoded in an Android resource ID
	 */
	case class ResourceId(packageId: Int, typeId: Int, itemIndex: Int) {
		override def toString: String = {
			"Package " + this.packageId + ", type " + this.typeId + ", item " + this.itemIndex
		}
	}
	
	def ARSCFileParser() = {}

	def parse(apkUri: FileResourceUri) = {
		AbstractAndroidXMLParser.handleAndroidXMLFiles(new File(new URI(apkUri)), Set("resources.arsc"), new AndroidXMLHandler() {

			override def handleXMLFile(fileName: String, fileNameFilter: Set[String], stream: InputStream) = {
				try {
					if (fileNameFilter.contains(fileName))
						doParse(stream)
				}
				catch {
				  case ex: IOException =>
//						err_msg_critical(TITLE, "Could not read resource file: " + ex.getMessage())
						ex.printStackTrace()
				}
			}
			
		})
	}
	
	def doParse(stream: InputStream) = readResourceHeader(stream)

	private def readResourceHeader(stream: InputStream): Unit = {
		val BLOCK_SIZE = 2048
		
		val resourceHeader = new ResTable_Header()
		readChunkHeader(stream, resourceHeader.header)
		resourceHeader.packageCount = readUInt32(stream)
//		if (DEBUG)
//			msg_normal(TITLE, "Package Groups (" + resourceHeader.packageCount + ")")
		
		// Do we have any packages to read?
		var remainingSize = resourceHeader.header.size - resourceHeader.header.headerSize
		if (remainingSize <= 0)
			return
		
		// Load the remaining data
		val remainingData = new Array[Byte](remainingSize)
		var totalBytesRead = 0
		while (totalBytesRead < remainingSize) {
			val block = new Array[Byte](Math.min(BLOCK_SIZE, remainingSize - totalBytesRead))
			val bytesRead = stream.read(block)
			if (bytesRead == 0 && bytesRead < block.length) {
//				err_msg_critical(TITLE, "Could not read block from resource file")
				return
			}
			System.arraycopy(block, 0, remainingData, totalBytesRead, bytesRead)
			totalBytesRead += bytesRead
		}
		var offset = 0
		var beforeBlock = 0
		
		// Read the next chunk
		var packageCtr = 0
		var keyStrings: Map[Int, String] = Map()
		var typeStrings: Map[Int, String] = Map()
		while (offset < remainingData.length - 1) {
			beforeBlock = offset
			val nextChunkHeader = new ResChunk_Header()
			offset = readChunkHeader(nextChunkHeader, remainingData, offset)
			if (nextChunkHeader.typ == RES_STRING_POOL_TYPE) {
				// Read the string pool header
				val stringPoolHeader = new ResStringPool_Header()
				stringPoolHeader.header = nextChunkHeader
				offset = parseStringPoolHeader(stringPoolHeader, remainingData, offset)
				
				// Read the string data
				val tempTable = mmapEmpty ++ this.stringTable
				offset = readStringTable(remainingData, offset, beforeBlock,
						stringPoolHeader, tempTable)
				this.stringTable = tempTable.toMap
				if(this.stringTable.size != stringPoolHeader.stringCount) throw new RuntimeException
			} else if (nextChunkHeader.typ == RES_TABLE_PACKAGE_TYPE) {
				// Read the package header
				val packageTable = new ResTable_Package()
				packageTable.header = nextChunkHeader
				offset = parsePackageTable(packageTable, remainingData, offset)
				
//				if (DEBUG)
//					msg_normal(TITLE, "\tPackage " + packageCtr + " id=" + packageTable.id
//							+ " name=" + packageTable.name)
				
				// Record the end of the object to know then to stop looking for
				// internal records
				val endOfRecord = beforeBlock + nextChunkHeader.size
				
				// Create the data object and set the base data
				val resPackage = new ResPackage()
				this.packages ::= resPackage
				resPackage.packageId = packageTable.id
				resPackage.packageName = packageTable.name
				
				{
					// Find the type strings
					var typeStringsOffset = beforeBlock + packageTable.typeStrings
					var beforeStringBlock = typeStringsOffset
					val typePoolHeader = new ResChunk_Header()
					typeStringsOffset = readChunkHeader(typePoolHeader, remainingData, typeStringsOffset)
					if (typePoolHeader.typ != RES_STRING_POOL_TYPE)
						throw new RuntimeException("Unexpected block type for package type strings")
					
					val typePool = new ResStringPool_Header()
					typePool.header = typePoolHeader
					typeStringsOffset = parseStringPoolHeader(typePool, remainingData, typeStringsOffset)
					
					// Attention: String offset starts at the beginning of the StringPool
					// block, not the at the beginning of the Package block referring to it.
					val tempTypeStrings = mmapEmpty ++ typeStrings
					readStringTable(remainingData, typeStringsOffset, beforeStringBlock,
							typePool, tempTypeStrings)
					typeStrings = tempTypeStrings.toMap
					// Find the key strings
					var keyStringsOffset = beforeBlock + packageTable.keyStrings
					beforeStringBlock = keyStringsOffset
					val keyPoolHeader = new ResChunk_Header()
					keyStringsOffset = readChunkHeader(keyPoolHeader, remainingData, keyStringsOffset)
					if (keyPoolHeader.typ != RES_STRING_POOL_TYPE)
						throw new RuntimeException("Unexpected block type for package key strings")
					
					val keyPool = new ResStringPool_Header()
					keyPool.header = keyPoolHeader
					keyStringsOffset = parseStringPoolHeader(keyPool, remainingData, keyStringsOffset)
					
					// Attention: String offset starts at the beginning of the StringPool
					// block, not the at the beginning of the Package block referring to it.
					val tempKeyStrings = mmapEmpty ++ keyStrings
					readStringTable(remainingData, keyStringsOffset, beforeStringBlock,
							keyPool, tempKeyStrings)
					keyStrings = tempKeyStrings.toMap
					// Jump to the end of the string block
					offset = beforeStringBlock + keyPoolHeader.size
				}
				
				while (offset < endOfRecord) {
					// Read the next inner block				
					val innerHeader = new ResChunk_Header()
					val beforeInnerBlock = offset
					offset = readChunkHeader(innerHeader, remainingData, offset)
					if (innerHeader.typ == RES_TABLE_TYPE_SPEC_TYPE) {
						// Type specification block
						val typeSpecTable = new ResTable_TypeSpec()
						typeSpecTable.header = innerHeader
						offset = readTypeSpecTable(typeSpecTable, remainingData, offset)
						assert(offset == beforeInnerBlock + typeSpecTable.header.headerSize)
						
						// Create the data object
						val tp = new ResType()
						tp.id = typeSpecTable.id
						tp.typeName = typeStrings(typeSpecTable.id - 1)
						resPackage.types ::= tp

						// Normally, we also have a set of configurations following, but
						// we don't implement that at the moment
					} else if (innerHeader.typ == RES_TABLE_TYPE_TYPE) {
						// Type resource entries. The id field maps to the type
						// for which we have a record. We create a mapping from
						// type IDs to declare resources.
						val typeTable = new ResTable_Type()
						typeTable.header = innerHeader
						offset = readTypeTable(typeTable, remainingData, offset)
						assert(offset == beforeInnerBlock + typeTable.header.headerSize)
						
						// Create the data object
						var resType: ResType = null
						for (rt <- resPackage.types)
							if (rt.id == typeTable.id) {
								resType = rt
							}
						if (resType == null)
							throw new RuntimeException("Reference to undeclared type found")
						val config = new ResConfig()
						resType.configurations ::= config
						
						// Read the table entries
						var resourceIdx = 0
						for (i <- 0 until typeTable.entryCount) {
							var entryOffset = readUInt32(remainingData, offset)
							offset += 4
							if (entryOffset == 0xFFFFFFFF){}	// NoEntry
							else {
							  var flag = true
								entryOffset += beforeInnerBlock + typeTable.entriesStart
								val entry = readEntryTable(remainingData, entryOffset)
								entryOffset += entry.size
								
								
								var res: AbstractResource = null
								
								// If this is a simple entry, the data structure is
								// followed by RES_VALUE
								if (entry.flagsComplex) {
									val cmpRes = new ComplexResource(mmapEmpty)
									res = cmpRes
									
									for (j <- 0 until entry.asInstanceOf[ResTable_Map_Entry].count) {
										val map = new ResTable_Map()
										entryOffset = readComplexValue(map, remainingData, entryOffset)
										cmpRes.value += (map.name + "" -> parseValue(map.value))
									}
								}
								else {
									val rval = new Res_Value()
									entryOffset = readValue(rval, remainingData, entryOffset)
									res = parseValue(rval)
									if (res == null) {
//										msg_normal(TITLE, "Could not parse resource " + keyStrings.get(entry.key)
//												+ "of type " + Integer.toHexString(rval.dataType) + ", skipping entry")
										flag = false
									}
								}
								
								// Create the data object. For finding the correct ID, we
								// must check whether the entry is really new - if so, it
								// gets a new ID, otherwise, we reuse the old one
								if(flag){
									if (keyStrings.keySet.contains(entry.key))
										res.resourceName = keyStrings(entry.key)
									else
										res.resourceName = "<INVALID RESOURCE>"
									for (r <- resType.getAllResources)
										if (r.getResourceName.equals(res.resourceName)) {
											res.resourceID = r.resourceID
										}
									if (res.resourceID <= 0)
										res.resourceID = (packageTable.id << 24) + (typeTable.id << 16) + resourceIdx
									config.resources ::= res
									resourceIdx+=1
								}
							}
						}
					}
					offset = beforeInnerBlock + innerHeader.size
				}
				
				// Create the data objects for the types in the package
//				for (resType <- resPackage.types) {
//					if (DEBUG) {
//						msg_normal(TITLE, "\t\tType " + resType.typeName + " " + (resType.id - 1) + ", configCount="
//							+ resType.configurations.size + ", entryCount="
//							+ (if(resType.configurations.size > 0) resType.configurations(0).resources.size else 0))
//						for (resConfig <- resType.configurations) {
//							msg_normal(TITLE, "\t\t\tconfig")
//							for (res <- resConfig.resources)
//								msg_normal(TITLE, "\t\t\t\tresource " + Integer.toHexString(res.resourceID)
//										+ " " + res.resourceName)
//						}
//					}
//				}
				packageCtr+=1
			}

			// Skip the block
			offset = beforeBlock + nextChunkHeader.size
			remainingSize -= nextChunkHeader.size
		}
	}

	/**
	 * Checks whether the given complex map entry is one of the well-known
	 * attributes.
	 * @param map The map entry to check
	 * @return True if the  given entry is one of the well-known attributes,
	 * otherwise false.
	 */
	protected def isAttribute(map: ResTable_Map): Boolean =
		(map.name == ATTR_TYPE
		|| map.name == ATTR_MIN
		|| map.name == ATTR_MAX
		|| map.name == ATTR_L10N
		|| map.name == ATTR_OTHER
		|| map.name == ATTR_ZERO
		|| map.name == ATTR_ONE
		|| map.name == ATTR_TWO
		|| map.name == ATTR_FEW
		|| map.name == ATTR_MANY)
	

	private def parseValue(rval: Res_Value): AbstractResource = {
		var res: AbstractResource = null
		 rval.dataType match {
			case TYPE_NULL =>
				res = new NullResource()
			case TYPE_REFERENCE =>
				res = new ReferenceResource(rval.data)
			case TYPE_ATTRIBUTE =>
				res = new AttributeResource(rval.data)
			case TYPE_STRING =>
				res = new StringResource(stringTable(rval.data))
			case TYPE_INT_DEC | TYPE_INT_HEX =>
				res = new IntegerResource(rval.data)
			case TYPE_INT_BOOLEAN =>
				res = new BooleanResource(rval.data != 0)
			case TYPE_INT_COLOR_ARGB8 =>
				res = new ColorResource(rval.data & 0xFF000000 >> 3 * 8, rval.data & 0x00FF0000 >> 2 * 8, rval.data & 0x0000FF00 >> 8, rval.data & 0x000000FF)
			case TYPE_INT_COLOR_RGB8 =>
				res = new ColorResource(0, rval.data & 0xFF0000 >> 2 * 8, rval.data & 0x00FF00 >> 8, rval.data & 0x0000FF)
			case TYPE_INT_COLOR_ARGB4 =>
				res = new ColorResource(rval.data & 0xF000 >> 3 * 8, rval.data & 0x0F00 >> 2 * 8, rval.data & 0x00F0 >> 8, rval.data & 0x000F)
			case TYPE_INT_COLOR_RGB4 =>
				res = new ColorResource(0, rval.data & 0xF00 >> 2 * 8, rval.data & 0x0F0 >> 8, rval.data & 0x00F)
			case TYPE_DIMENSION =>
				res = new DimensionResource(rval.data & COMPLEX_UNIT_MASK, rval.data >> COMPLEX_UNIT_SHIFT)
			case TYPE_FLOAT =>
				res = new FloatResource(rval.data.toFloat)
			case _ =>
		}
		res
	}

	private def readComplexValue(map: ResTable_Map, remainingData: Array[Byte], offset: Int): Int = {
	  var temp = offset
		map.name = readUInt32(remainingData, temp)
		temp += 4
		
		readValue(map.value, remainingData, temp)
	}

	private def readValue(rval: Res_Value, remainingData: Array[Byte], offset: Int): Int = {
		val initialOffset = offset
		var temp = offset
		rval.size = readUInt16(remainingData, temp)
		temp += 2
		if (rval.size > 8)	// This should always be 8. Check to not fail on broken resources in apps
			return 0
		
		rval.res0 = readUInt8(remainingData, temp)
		if (rval.res0 != 0)
			throw new RuntimeException("File format error, res0 was not zero")
		temp += 1

		rval.dataType = readUInt8(remainingData, temp)
		temp += 1

		rval.data = readUInt32(remainingData, temp)
		temp += 4
		
		assert(temp == initialOffset + rval.size)
		temp
	}

	private def readEntryTable(data: Array[Byte], offset: Int): ResTable_Entry = {
		// The exact type of entry depends on the size
	  var temp = offset
		val size = readUInt16(data, temp)
		
		temp += 2
		var entry: ResTable_Entry = null
		if (size == 0x8)
			entry = new ResTable_Entry()
		else if (size == 0x10)
			entry = new ResTable_Map_Entry()
		else
			throw new RuntimeException("Unknown entry type")
		entry.size = size
		
		val flags = readUInt16(data, temp)
		temp += 2
		entry.flagsComplex = (flags & FLAG_COMPLEX) == FLAG_COMPLEX
		entry.flagsPublic = (flags & FLAG_PUBLIC) == FLAG_PUBLIC
		
		entry.key = readUInt32(data, temp)
		temp += 4
		
		entry match {
			case mapEntry: ResTable_Map_Entry =>
				mapEntry.parent = readUInt32(data, temp)
				temp += 4
				mapEntry.count = readUInt32(data, temp)
				temp += 4
			case _ =>
		}
		
		entry
	}

	private def readTypeTable(typeTable: ResTable_Type, data: Array[Byte], offset: Int): Int = {
	  var temp = offset
		typeTable.id = readUInt8(data, temp)
		temp += 1
		
		typeTable.res0 = readUInt8(data, temp)
		if (typeTable.res0 != 0)
			throw new RuntimeException("File format error, res0 was not zero")
		temp += 1
				
		typeTable.res1 = readUInt16(data, temp)
		if (typeTable.res1 != 0)
			throw new RuntimeException("File format error, res1 was not zero")
		temp += 2
		
		typeTable.entryCount = readUInt32(data, temp)
		temp += 4

		typeTable.entriesStart = readUInt32(data, temp)
		temp += 4
		
		readConfigTable(typeTable.config, data, temp)
	}

	private def readConfigTable(config: ResTable_Config, data: Array[Byte], offset: Int): Int = {
	  var temp = offset
		config.size = readUInt32(data, temp)
		temp += 4
		
		config.mmc = readUInt16(data, temp)
		temp += 2
		
		config.mnc = readUInt16(data, temp)
		temp += 2
		
		config.language(0) = data(temp).toChar
				
		config.language(1) = data(temp + 1).toChar
		temp += 2
		
		config.country(0) = data(temp).toChar
		config.country(1) = data(temp + 1).toChar
		temp += 2
		
		config.orientation = readUInt8(data, temp)
		temp += 1
		config.touchscreen = readUInt8(data, temp)
		temp += 1
		config.density = readUInt16(data, temp)
		temp += 2

		config.keyboard = readUInt8(data, temp)
		temp += 1
		config.navigation = readUInt8(data, temp)
		temp += 1
		config.inputFlags = readUInt8(data, temp)
		temp += 1
		config.inputPad0 = readUInt8(data, temp)
		temp += 1

		config.screenWidth = readUInt16(data, temp)
		temp += 2
		config.screenHeight= readUInt16(data, temp)
		temp += 2

		config.sdkVersion = readUInt16(data, temp)
		temp += 2
		config.minorVersion = readUInt16(data, temp)
		temp += 2
		if (config.size <= 28)
			return temp

		config.screenLayout = readUInt8(data, temp)
		temp += 1
		config.uiMode = readUInt8(data, temp)
		temp += 1
		config.smallestScreenWidthDp = readUInt16(data, temp)
		temp += 2
		if (config.size <= 32)
			return temp
		
		config.screenWidthDp = readUInt16(data, temp)
		temp += 2
		config.screenHeightDp = readUInt16(data, temp)
		temp += 2

		temp
	}

	private def readTypeSpecTable(typeSpecTable: ResTable_TypeSpec, data: Array[Byte], offset: Int): Int = {
	  var temp = offset
		typeSpecTable.id = readUInt8(data, temp)
		temp += 1
		
		typeSpecTable.res0 = readUInt8(data, temp)
		temp += 1
		if (typeSpecTable.res0 != 0)
			throw new RuntimeException("File format violation, res0 was not zero")
		
		typeSpecTable.res1 = readUInt16(data, temp)
		temp += 2
		if (typeSpecTable.res1 != 0)
			throw new RuntimeException("File format violation, res1 was not zero")
		
		typeSpecTable.entryCount = readUInt32(data, temp)
		temp += 4

		temp
	}

	private def readStringTable(remainingData: Array[Byte], offset: Int, blockStart: Int,
	    												stringPoolHeader: ResStringPool_Header, stringList: MMap[Int, String]): Int = {
	  var temp = offset
		// Read the strings
		for (i <- 0 until stringPoolHeader.stringCount) {
			var stringIdx = readUInt32(remainingData, temp)
			temp += 4
			
			// Offset begins at block start
			stringIdx += stringPoolHeader.stringsStart + blockStart
			var str = ""
			if (stringPoolHeader.flagsUTF8)
				str = readStringUTF8(remainingData, stringIdx).trim()
			else
				str = readString(remainingData, stringIdx).trim()
			stringList.put(i, str)
		}
		temp
	}

	private def parsePackageTable(packageTable: ResTable_Package, data: Array[Byte], offset: Int): Int = {
	  var temp = offset
		packageTable.id = readUInt32(data, temp)
		temp += 4
		
		// Read the package name, zero-terminated string
		val bld = new StringBuilder()
		for (i <- 0 to 127) {
			val curChar = readUInt16(data, temp)
			bld.append(curChar.toChar)
			temp += 2
		}
		packageTable.name = bld.toString().trim()
		
		packageTable.typeStrings = readUInt32(data, temp)
		temp += 4

		packageTable.lastPublicType = readUInt32(data, temp)
		temp += 4

		packageTable.keyStrings = readUInt32(data, temp)
		temp += 4

		packageTable.lastPublicKey = readUInt32(data, temp)
		temp += 4

		temp
	}

	private def readString(remainingData: Array[Byte], stringIdx: Int): String = {
	  var temp = stringIdx
		val strLen = readUInt16(remainingData, temp)
		if (strLen == 0)
			return ""
		temp += 2
		val str = new Array[Byte](strLen * 2)
		System.arraycopy(remainingData, temp, str, 0, strLen * 2)
		new String(remainingData, temp, strLen * 2, "UTF-16LE")
	}

	private def readStringUTF8(remainingData: Array[Byte], stringIdx: Int): String = {
		// skip the length, will usually be 0x1A1A
		// int strLen = readUInt16(remainingData, stringIdx)
	  var temp = stringIdx
		temp += 2
		
		val builder = new StringBuilder()
		while (remainingData(temp) != 0){
			builder.append(remainingData(temp).toChar)
			temp += 1
		}
		builder.toString()
	}

	private def parseStringPoolHeader(stringPoolHeader: ResStringPool_Header, data: Array[Byte], offset: Int): Int = {
		stringPoolHeader.stringCount = readUInt32(data, offset)
		stringPoolHeader.styleCount = readUInt32(data, offset + 4)
		
		val flags = readUInt32(data, offset + 8)
		stringPoolHeader.flagsSorted = (flags & SORTED_FLAG) == SORTED_FLAG
		stringPoolHeader.flagsUTF8 = (flags & UTF8_FLAG) == UTF8_FLAG
		
		stringPoolHeader.stringsStart = readUInt32(data, offset + 12)
		stringPoolHeader.stylesStart = readUInt32(data, offset + 16)
		offset + 20
	}

	/**
	 * Reads a chunk header from the input stream and stores the data in the
	 * given object.
	 * @param stream The stream from which to read the chunk header
	 * @param nextChunkHeader The data object in which to put the chunk header
	 * @throws IOException Thrown if an error occurs during read
	 */
	private def readChunkHeader(stream: InputStream, nextChunkHeader: ResChunk_Header): Int = {
		val header = new Array[Byte](8)
		stream.read(header)
		readChunkHeader(nextChunkHeader, header, 0)
	}

	/**
	 * Reads a chunk header from the input stream and stores the data in the
	 * given object.
	 * @param nextChunkHeader The data object in which to put the chunk header
	 * @param data The data array containing the structure
	 * @param offset The offset from which to start reading
	 * @throws IOException Thrown if an error occurs during read
	 */
	private def readChunkHeader(nextChunkHeader: ResChunk_Header, data: Array[Byte], offset: Int): Int = {
	  var temp = offset
		nextChunkHeader.typ = readUInt16(data, temp)
		temp += 2
		
		nextChunkHeader.headerSize = readUInt16(data, temp)
		temp += 2

		nextChunkHeader.size = readUInt32(data, temp)
		temp += 4
		temp
	}

	private def readUInt8(uint16: Array[Byte], offset: Int): Int = {
		uint16(0 + offset) & 0x000000FF
	}

	private def readUInt16(uint16: Array[Byte], offset: Int): Int = {
		val b0 = uint16(0 + offset) & 0x000000FF
		val b1 = uint16(1 + offset) & 0x000000FF
		(b1 << 8) + b0
	}

	private def readUInt32(stream: InputStream): Int = {
		val uint32 = new Array[Byte](4)
		stream.read(uint32)
		readUInt32(uint32, 0)
	}

	private def readUInt32(uint32: Array[Byte], offset: Int): Int = {
		val b0 = uint32(0 + offset) & 0x000000FF
		val b1 = uint32(1 + offset) & 0x000000FF
		val b2 = uint32(2 + offset) & 0x000000FF
		val b3 = uint32(3 + offset) & 0x000000FF
		(Math.abs(b3) << 24) + (Math.abs(b2) << 16) + (Math.abs(b1) << 8) + Math.abs(b0)
	}
	
	def getGlobalStringPool: Map[Int, String] = {
		this.stringTable
	}
	
	def getPackages: List[ResPackage] = {
		this.packages
	}
	
	/**
	 * Finds the resource with the given Android resource ID. This method is
	 * configuration-agnostic and simply returns the first match it finds.
	 * @param resourceId The Android resource ID for which to the find the
	 * resource object
	 * @return The resource object with the given Android resource ID if it
	 * has been found, otherwise null.
	 */
	def findResource(resourceId: Int): AbstractResource = {
		val id = parseResourceId(resourceId)
		for (resPackage <- this.packages)
			if (resPackage.packageId == id.packageId) {
				for (resType <- resPackage.types)
					if (resType.id == id.typeId) {
						return resType.getFirstResource(resourceId)
					}
			}
		null
	}
	
	/**
	 * Parses an Android resource ID into its components
	 * @param resourceId The numeric resource ID to parse
	 * @return The data contained in the given Android resource ID
	 */
	def parseResourceId(resourceId: Int): ResourceId = {
		new ResourceId((resourceId & 0xFF000000) >> 24, (resourceId & 0x00FF0000) >> 16, resourceId & 0x0000FFFF)
	}
}
