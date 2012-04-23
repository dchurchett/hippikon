/** 
 * Part of the Hippikon API, a powerful authoriation
 * security framework for Java applications.
 *
 * Copyright (C) 2005  Dale Churchett
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Contact: Dale Churchett <dale@hippikon.com>
 * Website: http://www.hippikon.com, http://www.hippikon.org
 *
 */
package com.hippikon.io;
 
 import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.springframework.core.io.ClassPathResource;
 
 /**
  * Provides a utility method for file based I/O
  * operations that need to find a file in the system classpath. With the 
  * <code>findFileInClasspath()</code> method, a named file need only be located
  * on the classpath, negating the need for providing absolute paths, reletive paths
  * or messing around with various system properties.<p>
  *
  * If an application needs to add search paths to the system classpath, the
  * <code>fileutil.search.path</code> attribute may be specified as an
  * environment variable, where the values are additional absolute pathnames to
  * directories in which to search. This class is platform independent.<p>
  *
  * <b>Example:</b><p>
  *
  * File myFile = FileUtil.findFileInClasspath("my-properties-file.txt");<p>
  * 
  * @author Dale Churchett
  * @version $Id: FileUtil.java,v 1.4 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 public abstract class FileUtil {
 
     /**
      * Returns a File object located on the system classpath by a specified
      * filename. If the file is not found in a classpath directory, the "fileutil.search.path"
      * environment variable is checked if set.<p>
      *
      * The filename passed as a method parameter should and not 
      * contain any path information (e.g., "myfile.txt").<p>
      *
      * @param filename a relative filename (e.g., myfile.txt)
      *
      * @exception FileNotFoundException thrown if the file could not be
      * found or a file reference obtained
      */
     public static final File findFileInClasspath(String filename) throws IOException {
    	 ClassPathResource res = new ClassPathResource(filename);
    	 return res.getFile();
     }
 
 }

