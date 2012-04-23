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
package com.hippikon.security;
 
 import java.lang.annotation.Annotation;
 
 /**
  * This class is provided as a utility to find the overridden resource
  * name of a ProtectedResource. This was necessary in versions of Hippikon earlier than
  * 4.0, where annotations were introduced, but it turns out this wrapper is a convenient
  * way of determining the value of the annotation name() attribute.<p>
  *
  * This class uses reflection to invoke the annotation attribute.
  *  
  * @author Dale Churchett
  * @version $Id: ProtectedResourceWrapper.java,v 1.3 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  *
  */
 public class ProtectedResourceWrapper {
 
	 // the name value returned from the annotation
	 //
     private String resName;
  
     /**
      * Creates a new ProtectedResourceWrapper object for a
      * ProtectedResource object
      *
      * @param res a ProtectedResource instance
      *
      * @exception ProtectedResourceNamingException thrown if the getResourceName()
      * dynamic method invocation fails.
      */
     public ProtectedResourceWrapper(Object res)
     throws ProtectedResourceNamingException {
         this.resName = getResourceName(res.getClass(), res);
     }
 
     /**
      * Creates a new ProtectedResourceWrapper object for a
      * Class that may be a subtype of ProtectedResource 
      * 
      * @param c a Class that must be a subtype of ProtectedResource
      *
      * @exception ProtectedResourceNamingException thrown if the Class
      * is not a subclass of ProtectedResource or the getResourceName()
      * method invocation fails
      */
     @SuppressWarnings("unchecked")
	public ProtectedResourceWrapper(Class c) throws ProtectedResourceNamingException {
         this.resName = getResourceName(c, null);
    }
 
     /**
      * Returns the name of a ProtectedResource
      *
      * @return the name of the ProtectedResource class or object provided
      * in one of the constructor methods
      */
     String getResourceName() {
         return this.resName;
     }
     
     /**
      * Performs the logic necessary to retrieve the annotated value of the name() attribute 
      * from an incoming object permissions are being obtained for
      * 
      * @param c the class that has the annotation
      * @param o the object to find the annotation for
      * @return String value of the annotation, used to hook into the policy store and policy callbacks
      * 
      * @throws Exception
      */
 	@SuppressWarnings("unchecked")
	private static String getAnnotatedName(Class c, Object o) throws Exception {

 		Annotation a = c.getAnnotation(ProtectedResource.class);
 		String value = (String) a.annotationType().getMethod("name").invoke(a);
 		
 		return value;
	}
 
     /**
      * Uses the Java Reflection API to obtain the return value of the 
      * getResourceName() method defined on a ProtectedResource class
      *
      * @param c a subclass of ProtectedResource
      *
      * @exception ProtectedResourceNamingException thrown if the method
      * invocation fails
      */
     public static String getResourceName(Class<?> c, Object o) throws ProtectedResourceNamingException {
    	 
    	 try {
			return getAnnotatedName(c, o);
		} catch (Exception e) {
			throw new ProtectedResourceNamingException("Could not find annotated resource name for class: " + c.getName());
		}
     }
 

 
 }

