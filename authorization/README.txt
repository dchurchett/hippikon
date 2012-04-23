Hippikon Authorization API 
--------------------------

Released under Version 2.1 of the GNU LGPL
Webpage: http://www.hippikon.com
Author: Dale Churchett <dale@hippikon.com>

Achive files extract to the following directory structure:

hippikon-3.x
  |
  + javadoc               (generated javadocs)
  + lib                   (compiled hippikon.jar plus dependencies)
  + license.txt           (the LGPL License in full)
  + README.txt            (general notes)
  + build.xml             (the main build file for the system)
  + Hippikon_Manual.pdf   (a PDF copy of the online developer manual)
  + src                   (the source code)
    |
    + java-src            (contains the hippikon source code)
    + test-src            (contains the hippikon test code)
       |
       + config           (test XML policy store and resource.policies)

To install, extract to the file system, copy lib/*.jar to your application classpath resolving 
any possible conflicts with other versions of junit, xerces, log4j or ant.
To launch the Swing GUI permissions viewer, ensure hippikon.jar, xerces.jar and 
log4j.jar are in your classpath or pass to the JVM as the -classpath argument:

java com.hippikon.security.PermsNavigator

You will then be able to navigate to one of the example policy store XML 
files stored under src/test-src/config.

Hippikon 4.0 Change Log
-----------------------

- Major release that brings Hippikon up to JDK 1.6 compatibility and uses Annotations
- ProtectedResource now an Annotation
- Spring now used to load resources from the classpath
- Converted to maven directory format


Hippikon 3.3 Change Log
-----------------------

- Adds major functionality to the PermsNavigator tool in that the editor is now
  an XML Policy Store authoring tool.

Hippikon 3.2 Change Log
-----------------------

- fixed error with ant jar target that was not populating the hippikon.jar file correctly

Hippikon 3.1 Change Log
-----------------------

- fixed compile errors and warnings for JDK 1.5
- regression tested with JDK 1.4 and JDK 1.5
- JDK 1.2.2 no longer supported with Hippikon 3.1 and moving fowards

Hippikon 3.0 Change Log
-----------------------

Very few changes were made, those being to repackage and remove some proprietary references. 
Other changes include:

- The logging system was updated to use log4j and a log4j.conf is provided to get 
  the component working out-of-the-box
- The unit tests now use the latest version of JUnit to avoid all the pesky javac 
  warnings due to the assert keyword having been introduced in the JDK 1.4
- XML Parsing is delegated to Xerces-J.
- the Ant build script is updated to create the tar and zip bundles and to launch 
  the Swing GUI for viewing XML policy store files
- Added the LGPL license header to all files
- Added getDefinedPrinicipals() to the PolicyStore interface to support the PermsNavigator
  Library Dependencies

The following APIs are bundled with Hippikon in the lib directory:
Junit 3.8.1
log4j-1.2.9
xerces-j 2.6.2

The build file is written for ant 1.6.2 and provided you have junit.jar in your
$ANT_HOME/lib directory, it will run from the command line with no difficulty.

The supported Ant targets are:

- compile
- clean
- test-compile
- test
- create-bundle
- run-gui
- jar

See the build file for descriptions.

Hippikon was primarily developed using GVIM, but more recently with Netbeans 4.1 running
on Mac OSX. 
