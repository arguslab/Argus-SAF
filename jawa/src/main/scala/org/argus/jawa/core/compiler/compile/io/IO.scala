/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.compile.io

import Using._
import ErrorHandling.translate
import java.io.{File => JavaFile, _}
import java.io.{ObjectInputStream, ObjectStreamClass}
import java.net.{URI, URISyntaxException, URL}
import java.util.Properties
import java.nio.charset.Charset
import java.util.jar.{Attributes, JarEntry, JarOutputStream, Manifest}
import java.util.zip.{CRC32, ZipEntry, ZipInputStream, ZipOutputStream}

import scala.collection.immutable.TreeSet
import scala.reflect.{Manifest => SManifest}
import Function.tupled
import scala.collection.mutable
import scala.language.postfixOps
import scala.util.control.NonFatal

/** A collection of JavaFile, URL, and I/O utility methods.*/
object IO
{
  /** The maximum number of times a unique temporary filename is attempted to be created.*/
  private val MaximumTries = 10
  /** The producer of randomness for unique name generation.*/
  private lazy val random = new java.util.Random
  val temporaryDirectory = new JavaFile(System.getProperty("java.io.tmpdir"))
  /** The size of the byte or char buffer used in various methods.*/
  private val BufferSize = 8192
  /** JavaFile scheme name */
  private[this] val FileScheme = "file"

  /** The newline string for this system, as obtained by the line.separator system property. */
  val Newline: String = System.getProperty("line.separator")

  val utf8: Charset = Charset.forName("UTF-8")

  /** Returns a URL for the directory or jar containing the the class file `cl`.
  * If the location cannot be determined, an error is generated.
  * Note that Java standard library classes typically do not have a location associated with them.*/
  def classLocation(cl: Class[_]): URL =
  {
    val codeSource = cl.getProtectionDomain.getCodeSource
    if(codeSource == null) sys.error("No class location for " + cl)
    else codeSource.getLocation
  }

  /** Returns the directory or jar file containing the the class file `cl`.
  * If the location cannot be determined or it is not a file, an error is generated.
  * Note that Java standard library classes typically do not have a location associated with them.*/
  def classLocationFile(cl: Class[_]): JavaFile = toFile(classLocation(cl))
  
  /** Returns a URL for the directory or jar containing the class file for type `T` (as determined by an implicit Manifest).
  * If the location cannot be determined, an error is generated.
  * Note that Java standard library classes typically do not have a location associated with them.*/
  def classLocation[T](implicit mf: SManifest[T]): URL = classLocation(mf.runtimeClass)

  /** Returns the directory or jar file containing the the class file for type `T` (as determined by an implicit Manifest).
  * If the location cannot be determined, an error is generated.
  * Note that Java standard library classes typically do not have a location associated with them.*/
  def classLocationFile[T](implicit mf: SManifest[T]): JavaFile = classLocationFile(mf.runtimeClass)

  /** Constructs a JavaFile corresponding to `url`, which must have a scheme of `file`.
  * This method properly works around an issue with a simple conversion to URI and then to a JavaFile. */
  def toFile(url: URL): JavaFile =
    try { new JavaFile(url.toURI) }
    catch { case _: URISyntaxException => new JavaFile(url.getPath) }

  /** Converts the given URL to a JavaFile.  If the URL is for an entry in a jar, the JavaFile for the jar is returned. */
  def asFile(url: URL): JavaFile = urlAsFile(url) getOrElse sys.error("URL is not a file: " + url)
  def urlAsFile(url: URL): Option[JavaFile] =
    url.getProtocol match
    {
      case FileScheme => Some(toFile(url))
      case "jar" =>
        val path = url.getPath
        val end = path.indexOf('!')
        Some(uriToFile(if(end == -1) path else path.substring(0, end)))
      case _ => None
    }

  private[this] def uriToFile(uriString: String): JavaFile =
  {
    val uri = new URI(uriString)
    assert(uri.getScheme == FileScheme, "Expected protocol to be '" + FileScheme + "' in URI " + uri)
    if(uri.getAuthority eq null)
      new JavaFile(uri)
    else {
      /* https://github.com/sbt/sbt/issues/564
      * http://blogs.msdn.com/b/ie/archive/2006/12/06/file-uris-in-windows.aspx
      * http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=5086147
      * The specific problem here is that `uri` will have a defined authority component for UNC names like //foo/bar/some/path.jar
      * but the JavaFile constructor requires URIs with an undefined authority component.
      */
      new JavaFile(uri.getSchemeSpecificPart)
    }
  }

  def assertDirectory(file: JavaFile) { assert(file.isDirectory, (if(file.exists) "Not a directory: " else "Directory not found: ") + file) }
  def assertDirectories(file: JavaFile*) { file.foreach(assertDirectory) }

  // "base.extension" -> (base, extension)
  /** Splits the given string into base and extension strings.
  * If `name` contains no period, the base string is the input string and the extension is the empty string.
  * Otherwise, the base is the substring up until the last period (exclusive) and
  * the extension is the substring after the last period.
  *
  * For example, `split("Build.scala") == ("Build", "scala")`
  */
  def split(name: String): (String, String) =
  {
    val lastDot = name.lastIndexOf('.')
    if(lastDot >= 0)
      (name.substring(0, lastDot), name.substring(lastDot+1))
    else
      (name, "")
  }

  /** Each input file in `files` is created if it doesn't exist.
  * If a file already exists, the last modified time is set to the current time.
  * It is not guaranteed that all files will have the same last modified time after this call.*/
  def touch(files: Traversable[JavaFile]): Unit = files.foreach(f => touch(f))

  /** Creates a file at the given location if it doesn't exist.
  * If the file already exists and `setModified` is true, this method sets the last modified time to the current time.*/
  def touch(file: JavaFile, setModified: Boolean = true)
  {
    val absFile = file.getAbsoluteFile
    createDirectory(absFile.getParentFile)
    val created = translate("Could not create file " + absFile) { absFile.createNewFile() }
    if(created || absFile.isDirectory)
      ()
    else if(setModified && !absFile.setLastModified(System.currentTimeMillis))
      sys.error("Could not update last modified time for file " + absFile)
  }

  /** Creates directories `dirs` and all parent directories.  It tries to work around a race condition in `JavaFile.mkdirs()` by retrying up to a limit.*/
  def createDirectories(dirs: Traversable[JavaFile]): Unit =
    dirs.foreach(createDirectory)

  /** Creates directory `dir` and all parent directories.  It tries to work around a race condition in `JavaFile.mkdirs()` by retrying up to a limit.*/
  def createDirectory(dir: JavaFile): Unit =
  {
    def failBase = "Could not create directory " + dir
    // Need a retry because mkdirs() has a race condition
    var tryCount = 0
    while (!dir.exists && !dir.mkdirs() && tryCount < 100) { tryCount += 1 }
    if(dir.isDirectory)
      ()
    else if(dir.exists) {
      sys.error(failBase + ": file exists and is not a directory.")
    }
    else
      sys.error(failBase)
  }

  /** Gzips the file 'in' and writes it to 'out'.  'in' cannot be the same file as 'out'. */
  def gzip(in: JavaFile, out: JavaFile)
  {
    require(in != out, "Input file cannot be the same as the output file.")
    Using.fileInputStream(in) { inputStream =>
      Using.fileOutputStream()(out) { outputStream =>
        gzip(inputStream, outputStream)
      }
    }
  }
  /** Gzips the InputStream 'in' and writes it to 'output'.  Neither stream is closed.*/
  def gzip(input: InputStream, output: OutputStream): Unit =
    gzipOutputStream(output) { gzStream => transfer(input, gzStream) }

  /** Gunzips the file 'in' and writes it to 'out'.  'in' cannot be the same file as 'out'. */
  def gunzip(in: JavaFile, out: JavaFile)
  {
    require(in != out, "Input file cannot be the same as the output file.")
    Using.fileInputStream(in) { inputStream =>
      Using.fileOutputStream()(out) { outputStream =>
        gunzip(inputStream, outputStream)
      }
    }
  }
  /** Gunzips the InputStream 'input' and writes it to 'output'.  Neither stream is closed.*/
  def gunzip(input: InputStream, output: OutputStream): Unit =
    gzipInputStream(input) { gzStream => transfer(gzStream, output) }

  def unzip(from: JavaFile, toDirectory: JavaFile, filter: NameFilter = AllPassFilter, preserveLastModified: Boolean = true): Set[JavaFile] =
    fileInputStream(from)(in => unzipStream(in, toDirectory, filter, preserveLastModified))
  def unzipURL(from: URL, toDirectory: JavaFile, filter: NameFilter = AllPassFilter, preserveLastModified: Boolean = true): Set[JavaFile] =
    urlInputStream(from)(in => unzipStream(in, toDirectory, filter, preserveLastModified))
  def unzipStream(from: InputStream, toDirectory: JavaFile, filter: NameFilter = AllPassFilter, preserveLastModified: Boolean = true): Set[JavaFile] =
  {
    createDirectory(toDirectory)
    zipInputStream(from) { zipInput => extract(zipInput, toDirectory, filter, preserveLastModified) }
  }
  private def extract(from: ZipInputStream, toDirectory: JavaFile, filter: NameFilter, preserveLastModified: Boolean) =
  {
    val set = new mutable.HashSet[JavaFile]
    def next()
    {
      val entry = from.getNextEntry
      if(entry == null)
        ()
      else
      {
        val name = entry.getName
        if(filter.accept(name))
        {
          val target = new JavaFile(toDirectory, name)
          //log.debug("Extracting zip entry '" + name + "' to '" + target + "'")
          if(entry.isDirectory)
            createDirectory(target)
          else
          {
            set += target
            translate("Error extracting zip entry '" + name + "' to '" + target + "': ") {
              fileOutputStream()(target) { out => transfer(from, out) }
            }
          }
          if(preserveLastModified)
            target.setLastModified(entry.getTime)
        }
        else
        {
          //log.debug("Ignoring zip entry '" + name + "'")
        }
        from.closeEntry()
        next()
      }
    }
    next()
    Set() ++ set
  }

  /** Retrieves the content of the given URL and writes it to the given JavaFile. */
  def download(url: URL, to: JavaFile): Unit =
    Using.urlInputStream(url) { inputStream =>
      transfer(inputStream, to)
    }

  /** Copies the contents of `in` to `out`.*/
  def transfer(in: JavaFile, out: JavaFile): Unit =
    fileInputStream(in){ in => transfer(in, out) }

  /** Copies the contents of the input file `in` to the `out` stream.
  * The output stream is not closed by this method.*/
  def transfer(in: JavaFile, out: OutputStream): Unit =
    fileInputStream(in){ in => transfer(in, out) }

  /** Copies all bytes from the given input stream to the given JavaFile.  The input stream is not closed by this method.*/
  def transfer(in: InputStream, to: JavaFile): Unit =
    Using.fileOutputStream()(to) { outputStream =>
      transfer(in, outputStream)
    }

  /** Copies all bytes from the given input stream to the given output stream.
  * Neither stream is closed.*/
  def transfer(in: InputStream, out: OutputStream): Unit = transferImpl(in, out, close = false)
  /** Copies all bytes from the given input stream to the given output stream.  The
  * input stream is closed after the method completes.*/
  def transferAndClose(in: InputStream, out: OutputStream): Unit = transferImpl(in, out, close = true)
  private def transferImpl(in: InputStream, out: OutputStream, close: Boolean) {
    try {
      val buffer = new Array[Byte](BufferSize)
      def read() {
        val byteCount = in.read(buffer)
        if(byteCount >= 0)
        {
          out.write(buffer, 0, byteCount)
          read()
        }
      }
      read()
    }
    finally { if(close) in.close() }
  }

  /** Creates a temporary directory and provides its location to the given function.  The directory
  * is deleted after the function returns.*/
  def withTemporaryDirectory[T](action: JavaFile => T): T = {
    val dir = createTemporaryDirectory
    try { action(dir) }
    finally { delete(dir) }
  }

  /** Creates a directory in the default temporary directory with a name generated from a random integer. */
  def createTemporaryDirectory: JavaFile = createUniqueDirectory(temporaryDirectory)

  /** Creates a directory in `baseDirectory` with a name generated from a random integer */
  def createUniqueDirectory(baseDirectory: JavaFile): JavaFile = {
    def create(tries: Int): JavaFile = {
      if(tries > MaximumTries)
        sys.error("Could not create temporary directory.")
      else {
        val randomName = "sbt_" + java.lang.Integer.toHexString(random.nextInt)
        val f = new JavaFile(baseDirectory, randomName)

        try { createDirectory(f); f }
        catch { case _: Exception => create(tries + 1) }
      }
    }
    create(0)
  }
  /** Creates a file in the default temporary directory, calls `action` with the file, deletes the file, and returns the result of calling `action`.
  * The name of the file will begin with `prefix`, which must be at least three characters long, and end with `postfix`, which has no minimum length.  */
  def withTemporaryFile[T](prefix: String, postfix: String)(action: JavaFile => T): T = {
    val file = JavaFile.createTempFile(prefix, postfix)
    try { action(file) }
    finally { file.delete() }
  }

  private[io] def jars(dir: JavaFile): Iterable[JavaFile] = listFiles(dir, GlobFilter("*.jar"))

  /** Deletes all empty directories in the set.  Any non-empty directories are ignored. */
  def deleteIfEmpty(dirs: collection.Set[JavaFile]): Unit = {
    val isEmpty = new mutable.HashMap[JavaFile, Boolean]
    def visit(f: JavaFile): Boolean = isEmpty.getOrElseUpdate(f, dirs(f) && f.isDirectory && (f.listFiles forall visit) )

    dirs foreach visit
    for( (f, true) <- isEmpty) f.delete
  }

  /** Deletes each file or directory (recursively) in `files`.*/
  def delete(files: Iterable[JavaFile]): Unit = files.foreach(delete)

  /** Deletes each file or directory in `files` recursively.  Any empty parent directories are deleted, recursively.*/
  def deleteFilesEmptyDirs(files: Iterable[JavaFile]): Unit = {
    def isEmptyDirectory(dir: JavaFile) = dir.isDirectory && listFiles(dir).isEmpty
    def parents(fs: Set[JavaFile]) = fs flatMap { f => Option(f.getParentFile) }
    def deleteEmpty(dirs: Set[JavaFile]) {
      val empty = dirs filter isEmptyDirectory
      if(empty.nonEmpty) { // looks funny, but this is true if at least one of `dirs` is an empty directory
        empty foreach { _.delete() }
        deleteEmpty(parents(empty))
      }
    }

    delete(files)
    deleteEmpty(parents(files.toSet))
  }

  /** Deletes `file`, recursively if it is a directory. */
  def delete(file: JavaFile) {
    translate("Error deleting file " + file + ": ") {
      val deleted = file.delete()
      if(!deleted && file.isDirectory) {
        delete(listFiles(file))
        file.delete
      }
    }
  }

  /** Returns the children of directory `dir` that match `filter` in a non-null array.*/
  def listFiles(filter: java.io.FileFilter)(dir: JavaFile): Array[JavaFile] = wrapNull(dir.listFiles(filter))

  /** Returns the children of directory `dir` that match `filter` in a non-null array.*/
  def listFiles(dir: JavaFile, filter: java.io.FileFilter): Array[JavaFile] = wrapNull(dir.listFiles(filter))

  /** Returns the children of directory `dir` in a non-null array.*/
  def listFiles(dir: JavaFile): Array[JavaFile] = wrapNull(dir.listFiles())

  private[io] def wrapNull(a: Array[JavaFile]) =
    if(a == null)
      new Array[JavaFile](0)
    else
      a


  /** Creates a jar file.
  * @param sources The files to include in the jar file paired with the entry name in the jar.  Only the pairs explicitly listed are included.
  * @param outputJar The file to write the jar to.
  * @param manifest The manifest for the jar.*/
  def jar(sources: Traversable[(JavaFile,String)], outputJar: JavaFile, manifest: Manifest): Unit =
    archive(sources.toSeq, outputJar, Some(manifest))

  /** Creates a zip file.
  * @param sources The files to include in the zip file paired with the entry name in the zip.  Only the pairs explicitly listed are included.
  * @param outputZip The file to write the zip to.*/
  def zip(sources: Traversable[(JavaFile,String)], outputZip: JavaFile): Unit =
    archive(sources.toSeq, outputZip, None)

  private def archive(sources: Seq[(JavaFile,String)], outputFile: JavaFile, manifest: Option[Manifest]) {
    if(outputFile.isDirectory)
      sys.error("Specified output file " + outputFile + " is a directory.")
    else {
      val outputDir = outputFile.getParentFile
      createDirectory(outputDir)
      withZipOutput(outputFile, manifest) { output =>
        val createEntry: (String => ZipEntry) = if(manifest.isDefined) new JarEntry(_) else new ZipEntry(_)
        writeZip(sources, output)(createEntry)
      }
    }
  }
  private def writeZip(sources: Seq[(JavaFile, String)], output: ZipOutputStream)(createEntry: String => ZipEntry) {
    val files = sources.flatMap { case (file,name) => if (file.isFile) (file, normalizeName(name)) :: Nil else Nil }

    val now = System.currentTimeMillis
    // The CRC32 for an empty value, needed to store directories in zip files
    val emptyCRC = new CRC32().getValue

    def addDirectoryEntry(name: String) {
      output putNextEntry makeDirectoryEntry(name)
      output.closeEntry()
    }

    def makeDirectoryEntry(name: String) =
    {
//      log.debug("\tAdding directory " + relativePath + " ...")
      val e = createEntry(name)
      e setTime now
      e setSize 0
      e setMethod ZipEntry.STORED
      e setCrc emptyCRC
      e
    }

    def makeFileEntry(file: JavaFile, name: String) =
    {
//      log.debug("\tAdding " + file + " as " + name + " ...")
      val e = createEntry(name)
      e setTime file.lastModified
      e
    }
    def addFileEntry(file: JavaFile, name: String)
    {
      output putNextEntry makeFileEntry(file, name)
      transfer(file, output)
      output.closeEntry()
    }

    //Calculate directories and add them to the generated Zip
    allDirectoryPaths(files) foreach addDirectoryEntry

    //Add all files to the generated Zip
    files foreach { case (file, name) => addFileEntry(file, name) }
  }

  // map a path a/b/c to List("a", "b")
  private def relativeComponents(path: String): List[String] =
    path.split("/").toList.dropRight(1)

  // map components List("a", "b", "c") to List("a/b/c/", "a/b/", "a/", "")
  private def directories(path: List[String]): List[String] =
    path.foldLeft(List(""))( (e,l) => (e.head + l + "/") :: e )

  // map a path a/b/c to List("a/b/", "a/")
  private def directoryPaths(path: String): List[String] =
    directories(relativeComponents(path)).filter(_.length > 1)

  // produce a sorted list of all the subdirectories of all provided files
  private def allDirectoryPaths(files: Iterable[(JavaFile,String)]) =
    TreeSet[String]() ++ (files flatMap { case (_, name) => directoryPaths(name) })

  private def normalizeName(name: String) = {
    val sep = JavaFile.separatorChar
    if(sep == '/') name else name.replace(sep, '/')
  }

  private def withZipOutput(file: JavaFile, manifest: Option[Manifest])(f: ZipOutputStream => Unit) {
    fileOutputStream()(file) { fileOut =>
      val (zipOut, _) =
        manifest match
        {
          case Some(mf) =>
            import Attributes.Name.MANIFEST_VERSION
            val main = mf.getMainAttributes
            if(!main.containsKey(MANIFEST_VERSION))
              main.put(MANIFEST_VERSION, "1.0")
            (new JarOutputStream(fileOut, mf), "jar")
          case None => (new ZipOutputStream(fileOut), "zip")
        }
      try { f(zipOut) }
      finally { zipOut.close() }
    }
  }

  /** Returns the path for `file` relative to directory `base` or None if `base` is not a parent of `file`.
  * If `file` or `base` are not absolute, they are first resolved against the current working directory. */
  def relativize(base: JavaFile, file: JavaFile): Option[String] =
  {
    val pathString = file.getAbsolutePath
    baseFileString(base) flatMap
    {
      baseString =>
      {
        if(pathString.startsWith(baseString))
          Some(pathString.substring(baseString.length))
        else
          None
      }
    }
  }
  private def baseFileString(baseFile: JavaFile): Option[String] =
  {
    if(baseFile.isDirectory)
    {
      val cp = baseFile.getAbsolutePath
      assert(cp.length > 0)
      val normalized = if(cp.charAt(cp.length - 1) == JavaFile.separatorChar) cp else cp + JavaFile.separatorChar
      Some(normalized)
    }
    else
      None
  }

  /** For each pair in `sources`, copies the contents of the first JavaFile (the source) to the location of the second JavaFile (the target).
  * 
  * A source file is always copied if `overwrite` is true.
  * If `overwrite` is false, the source is only copied if the target is missing or is older than the source file according to last modified times.
  * If the source is a directory, the corresponding directory is created.
  *
  * If `preserveLastModified` is `true`, the last modified times are transferred as well.
  * Any parent directories that do not exist are created.
  * The set of all target files is returned, whether or not they were updated by this method.*/
  def copy(sources: Traversable[(JavaFile,JavaFile)], overwrite: Boolean = false, preserveLastModified: Boolean = false): Set[JavaFile] =
    sources.map( tupled(copyImpl(overwrite, preserveLastModified)) ).toSet

  private def copyImpl(overwrite: Boolean, preserveLastModified: Boolean)(from: JavaFile, to: JavaFile): JavaFile =
  {
    if(overwrite || !to.exists || from.lastModified > to.lastModified)
    {
      if(from.isDirectory)
        createDirectory(to)
      else
      {
        createDirectory(to.getParentFile)
        copyFile(from, to, preserveLastModified)
      }
    }
    to
  }

  /** Copies the contents of each file in the `source` directory to the corresponding file in the `target` directory.
  * A source file is always copied if `overwrite` is true.
  * If `overwrite` is false, the source is only copied if the target is missing or is older than the source file according to last modified times.
  * Files in `target` without a corresponding file in `source` are left unmodified in any case.
  * If `preserveLastModified` is `true`, the last modified times are transferred as well.
  * Any parent directories that do not exist are created. */
  def copyDirectory(source: JavaFile, target: JavaFile, overwrite: Boolean = false, preserveLastModified: Boolean = false): Unit =
    copy( (PathFinder(source) ***) x Path.rebase(source, target), overwrite, preserveLastModified)

  /** Copies the contents of `sourceFile` to the location of `targetFile`, overwriting any existing content.
  * If `preserveLastModified` is `true`, the last modified time is transferred as well.*/
  def copyFile(sourceFile: JavaFile, targetFile: JavaFile, preserveLastModified: Boolean = false)
  {
    // NOTE: when modifying this code, test with larger values of CopySpec.MaxFileSizeBits than default

    require(sourceFile.exists, "Source file '" + sourceFile.getAbsolutePath + "' does not exist.")
    require(!sourceFile.isDirectory, "Source file '" + sourceFile.getAbsolutePath + "' is a directory.")
    fileInputChannel(sourceFile) { in =>
      fileOutputChannel(targetFile) { out =>
        // maximum bytes per transfer according to  from http://dzone.com/snippets/java-filecopy-using-nio
        val max = (64 * 1024 * 1024) - (32 * 1024)
        val total = in.size
        def loop(offset: Long): Long =
          if(offset < total)
            loop( offset + out.transferFrom(in, offset, max) )
          else
            offset
        val copied = loop(0)
        if(copied != in.size)
          sys.error("Could not copy '" + sourceFile + "' to '" + targetFile + "' (" + copied + "/" + in.size + " bytes copied)")
      }
    }
    if(preserveLastModified)
      copyLastModified(sourceFile, targetFile)
  }
  /** Transfers the last modified time of `sourceFile` to `targetFile`. */
  def copyLastModified(sourceFile: JavaFile, targetFile: JavaFile): Boolean = {
    val last = sourceFile.lastModified
    // lastModified can return a negative number, but setLastModified doesn't accept it
    // see Java bug #6791812
    targetFile.setLastModified( math.max(last, 0L) )
  }
  /** The default Charset used when not specified: UTF-8. */
  def defaultCharset: Charset = utf8

  /** Writes `content` to `file` using `charset` or UTF-8 if `charset` is not explicitly specified.
  * If `append` is `false`, the existing contents of `file` are overwritten.
  * If `append` is `true`, the new `content` is appended to the existing contents.
  * If `file` or any parent directories do not exist, they are created. */
  def write(file: JavaFile, content: String, charset: Charset = defaultCharset, append: Boolean = false): Unit =
    writer(file, content, charset, append) { _.write(content)  }

  def writer[T](file: JavaFile, content: String, charset: Charset, append: Boolean = false)(f: BufferedWriter => T): T =
    if(charset.newEncoder.canEncode(content))
      fileWriter(charset, append)(file) { f }
    else
      sys.error("String cannot be encoded by charset " + charset.name)

  def reader[T](file: JavaFile, charset: Charset = defaultCharset)(f: BufferedReader => T): T =
    fileReader(charset)(file) { f }

  /** Reads the full contents of `file` into a String using `charset` or UTF-8 if `charset` is not explicitly specified. */
  def read(file: JavaFile, charset: Charset = defaultCharset): String =
  {
    val out = new ByteArrayOutputStream(file.length.toInt)
    transfer(file, out)
    out.toString(charset.name)
  }

  /** Reads the full contents of `in` into a byte array.  This method does not close `in`.*/
  def readStream(in: InputStream, charset: Charset = defaultCharset): String =
  {
    val out = new ByteArrayOutputStream
    transfer(in, out)
    out.toString(charset.name)
  }

  /** Reads the full contents of `in` into a byte array. */
  def readBytes(file: JavaFile): Array[Byte] = fileInputStream(file)(readBytes)

  /** Reads the full contents of `in` into a byte array.  This method does not close `in`. */
  def readBytes(in: InputStream): Array[Byte] =
  {
    val out = new ByteArrayOutputStream
    transfer(in, out)
    out.toByteArray
  }

  /** Appends `content` to the existing contents of `file` using `charset` or UTF-8 if `charset` is not explicitly specified.
  * If `file` does not exist, it is created, as are any parent directories. */
  def append(file: JavaFile, content: String, charset: Charset = defaultCharset): Unit =
    write(file, content, charset, append = true)

  /** Appends `bytes` to the existing contents of `file`.
  * If `file` does not exist, it is created, as are any parent directories. */
  def append(file: JavaFile, bytes: Array[Byte]): Unit =
    writeBytes(file, bytes, append = true)

  /** Writes `bytes` to `file`, overwriting any existing content.
  * If any parent directories do not exist, they are first created. */
  def write(file: JavaFile, bytes: Array[Byte]): Unit =
    writeBytes(file, bytes, append = false)

  private def writeBytes(file: JavaFile, bytes: Array[Byte], append: Boolean): Unit =
    fileOutputStream(append)(file) { _.write(bytes) }

  /** Reads all of the lines from `url` using the provided `charset` or UTF-8 if `charset` is not explicitly specified. */
  def readLinesURL(url: URL, charset: Charset = defaultCharset): List[String] =
    urlReader(charset)(url)(readLines)

  /** Reads all of the lines in `file` using the provided `charset` or UTF-8 if `charset` is not explicitly specified. */
  def readLines(file: JavaFile, charset: Charset = defaultCharset): List[String] =
    fileReader(charset)(file)(readLines)

  /** Reads all of the lines from `in`.  This method does not close `in`.*/
  def readLines(in: BufferedReader): List[String] = 
    foldLines[List[String]](in, Nil)( (accum, line) => line :: accum ).reverse

  /** Applies `f` to each line read from `in`. This method does not close `in`.*/ 
  def foreachLine(in: BufferedReader)(f: String => Unit): Unit =
    foldLines(in, ())( (_, line) => f(line) )
  
  /** Applies `f` to each line read from `in` and the accumulated value of type `T`, with initial value `init`.
  * This method does not close `in`.*/
  def foldLines[T](in: BufferedReader, init: T)(f: (T, String) => T): T =
  {
    def readLine(accum: T): T =
    {
      val line = in.readLine()
      if(line eq null) accum else readLine(f(accum, line))
    }
    readLine(init)
  }
  
  /** Writes `lines` to `file` using the given `charset` or UTF-8 if `charset` is not explicitly specified.
  * If `append` is `false`, the contents of the file are overwritten.
  * If `append` is `true`, the lines are appended to the file.
  * A newline is written after each line and NOT before the first line.
  * If any parent directories of `file` do not exist, they are first created. */
  def writeLines(file: JavaFile, lines: Seq[String], charset: Charset = defaultCharset, append: Boolean = false): Unit =
    writer(file, lines.headOption.getOrElse(""), charset, append) { w =>
      lines.foreach { line => w.write(line); w.newLine() }
    }

  /** Writes `lines` to `writer` using `writer`'s `println` method. */
  def writeLines(writer: PrintWriter, lines: Seq[String]): Unit =
    lines foreach writer.println
  
  /** Writes `properties` to the JavaFile `to`, using `label` as the comment on the first line.
  * If any parent directories of `to` do not exist, they are first created. */
  def write(properties: Properties, label: String, to: JavaFile): Unit =
    fileOutputStream()(to) { output => properties.store(output, label) }

  /** Reads the properties in `from` into `properties`.  If `from` does not exist, `properties` is left unchanged.*/
  def load(properties: Properties, from: JavaFile): Unit =
    if(from.exists)
      fileInputStream(from){ input => properties.load(input) }

  /** A pattern used to split a String by path separator characters.*/
  private val PathSeparatorPattern = java.util.regex.Pattern.compile(JavaFile.pathSeparator)

  /** Splits a String around the platform's path separator characters. */
  def pathSplit(s: String): Array[String] = PathSeparatorPattern.split(s)

  /** Move the provided files to a temporary location.
  *   If 'f' returns normally, delete the files.
  *   If 'f' throws an Exception, return the files to their original location.*/
  def stash[T](files: Set[JavaFile])(f: => T): T =
    withTemporaryDirectory { dir =>
      val stashed = stashLocations(dir, files.toArray)
      move(stashed)

      try { f } catch { case e: Exception =>
        try { move(stashed.map(_.swap)); throw e }
        catch { case NonFatal(_) => throw e }
      }
    }

  private def stashLocations(dir: JavaFile, files: Array[JavaFile]) =
    for( (file, index) <- files.zipWithIndex) yield
      (file, new JavaFile(dir, index.toHexString))

  // TODO: the reference to the other move overload does not resolve, probably due to a scaladoc bug
  /** For each pair in `files`, moves the contents of the first JavaFile to the location of the second.
  * See [[move(JavaFile,JavaFile)]] for the behavior of the individual move operations. */
  def move(files: Traversable[(JavaFile, JavaFile)]): Unit =
    files.foreach(Function.tupled(move))
  
  /** Moves the contents of `a` to the location specified by `b`.
  * This method deletes any content already at `b` and creates any parent directories of `b` if they do not exist.
  * It will first try `JavaFile.renameTo` and if that fails, resort to copying and then deleting the original file.
  * In either case, the original JavaFile will not exist on successful completion of this method.*/
  def move(a: JavaFile, b: JavaFile): Unit =
  {
    if(b.exists)
      delete(b)
    createDirectory(b.getParentFile)
    if(!a.renameTo(b))
    {
      copyFile(a, b, preserveLastModified = true)
      delete(a)
    }
  }

  /** Applies `f` to a buffered gzip `OutputStream` for `file`.
  * The streams involved are opened before calling `f` and closed after it returns.
  * The result is the result of `f`. */
  def gzipFileOut[T](file: JavaFile)(f: OutputStream => T): T =
    Using.fileOutputStream()(file) { fout =>
    Using.gzipOutputStream(fout) { outg =>
    Using.bufferedOutputStream(outg)(f) }}

  /** Applies `f` to a buffered gzip `InputStream` for `file`.
  * The streams involved are opened before calling `f` and closed after it returns.
  * The result is the result of `f`. */
  def gzipFileIn[T](file: JavaFile)(f: InputStream => T): T =
    Using.fileInputStream(file) { fin =>
    Using.gzipInputStream(fin) { ing =>
    Using.bufferedInputStream(ing)(f) }}
  
  /** Converts an absolute JavaFile to a URI.  The JavaFile is converted to a URI (toURI),
  * normalized (normalize), encoded (toASCIIString), and a forward slash ('/') is appended to the path component if
  * it does not already end with a slash.
  */
  def directoryURI(dir: JavaFile): URI  =
  {
    assertAbsolute(dir)
    directoryURI(dir.toURI.normalize)
  }

  /** Converts an absolute JavaFile to a URI.  The JavaFile is converted to a URI (toURI),
  * normalized (normalize), encoded (toASCIIString), and a forward slash ('/') is appended to the path component if
  * it does not already end with a slash.
  */
  def directoryURI(uri: URI): URI =
  {
    if(!uri.isAbsolute) return uri;//assertAbsolute(uri)
    val str = uri.toASCIIString
    val dirStr = if(str.endsWith("/") || uri.getScheme != FileScheme) str else str + "/"
    new URI(dirStr).normalize
  }
  /** Converts the given JavaFile to a URI.  If the JavaFile is relative, the URI is relative, unlike JavaFile.toURI*/
  def toURI(f: JavaFile): URI  =  
    // need to use the three argument URI constructor because the single argument version doesn't encode
    if(f.isAbsolute) f.toURI else new URI(null, normalizeName(f.getPath), null)

  /** Resolves `f` against `base`, which must be an absolute directory.
  * The result is guaranteed to be absolute.
  * If `f` is absolute, it is returned without changes.  */
  def resolve(base: JavaFile, f: JavaFile): JavaFile  =
  {
    assertAbsolute(base)
    val fabs = if(f.isAbsolute) f else new JavaFile(directoryURI(new JavaFile(base, f.getPath)))
    assertAbsolute(fabs)
    fabs
  }
  def assertAbsolute(f: JavaFile): Unit = assert(f.isAbsolute, "Not absolute: " + f)
  def assertAbsolute(uri: URI): Unit = assert(uri.isAbsolute, "Not absolute: " + uri)

  /** Parses a classpath String into JavaFile entries according to the current platform's path separator.*/
  def parseClasspath(s: String): Seq[JavaFile] = IO.pathSplit(s).map(new JavaFile(_)).toSeq

  /** Constructs an `ObjectInputStream` on `wrapped` that uses `loader` to load classes.
  * See also [[https://github.com/sbt/sbt/issues/136 issue 136]]. */
  def objectInputStream(wrapped: InputStream, loader: ClassLoader): ObjectInputStream = new ObjectInputStream(wrapped)
  {
    override def resolveClass(osc: ObjectStreamClass): Class[_] =
    {
      val c = Class.forName(osc.getName, false, loader)
      if(c eq null) super.resolveClass(osc) else c
    }
  }
}
