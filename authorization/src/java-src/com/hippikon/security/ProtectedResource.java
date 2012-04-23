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

import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
 
 /**
  * The ProtectedResource annotation must be defined by 
  * objects that need to have access permissions access  
  * determined by the Hippikon Authorization framework.<p>
  *
  * Hippikon provides a white-box framework for dynamic authorization. To plug new objects 
  * into the authorization framework, application developers must follow the following 
  * steps:<p>
  *
  * <ul>
  * <li>The new class must define the ProtectedResource annotation.
  * <li>In the case where specialized authorization logic is required, 
  * develop a {@link Policy} implementation by sub-classing {@link DefaultObjectPolicy}
  * overriding the appropriate methods.
  * <li>Create an entry in the appropriate hippikon.product.[productID].resource.policies file mapping
  * the custom Policy classname to the value returned by {@link ProtectedResource} name attribute.
  * <li>Define the set of user principal-permission entries (including roles) in a persistent 
  * policy store.
  * </ul><p>
  *
  * If no entry is made in the policies file, the DefaultObjectPolicy
  * is applied.
  *
  * @author Dale Churchett
  * @since JDK 1.6
  */
@Inherited
@Retention(RetentionPolicy.RUNTIME)
public @interface ProtectedResource {
 
     /**
      * Returns the name of the ProtectedResource, which is used as the key
      * to obtain permissions configured for various principals within
      * a policy store. The return value of this method is also used as
      * a key in the resource.policies file for each product to retrieve
      * the correct {@link Policy} implementation.<p>
      *
      * This value should be set to match 
      * exactly the same as the key value used to obtain permissions. For example, 
      * in the XML policy store implementation the return value of this method should be
      * the exactly same string value as the <code>name</code> attribute of the 
      * <code>protected-resource</code> XML node in the <code>policy-store</code> file. 
      *
      * @return the name of the ProtectedResource used to map Policy
      * classes in the resource.policies file. The default return value is 
      * "ProtectedResource", which subclasses will need to change or a ResourceNotFoundException
      * will be thrown.
      */
     public String name() default "ProtectedResource";
 
 }

