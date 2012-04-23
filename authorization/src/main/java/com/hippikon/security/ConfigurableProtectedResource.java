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
 
 /**
  * A default implementation of a Configurable class that is also
  * a ProtectedResource, and as such can be used within a List passed to the
  * {@link PermissionsFactory}.<p>
  * 
  * The class is designed to allow permissions to be obtained for objects, or a collection
  * of objects and/or attributes that do not exist as separate ProtectedResource objects.<p>
  *
  * A typical example of use for this class is to 'section' off parts of a user interface that
  * contain attributes of different objects, but all tied together to form a coherent read/edit
  * screen. Without the Configurable mechanism many small classes would need to be written
  * that only defined the <code>name()</code> attribute in order to configure
  * the permissions for the resource.<p>
  *
  * This class is made to be <code>final</code> as there is no point in sub-classing.
  *
  * @author Dale Churchett
  * @version $Id: ConfigurableProtectedResource.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
@ProtectedResource(name="ConfigurableProtectedResource")
 public final class ConfigurableProtectedResource  implements Configurable {
 
     private String name = null;
 
     /**
      * Create an instance of ConfigurableProtectedResource with the name used as the 
      * resource key in the policy-store definition.
      *
      * @param name the key to use in the policy store definition.
      */
     public ConfigurableProtectedResource(String name) {
         this.name = name;
     }
 
     /**
      * Returns the ProtectedResource key name configured in the PolicyStore.
      * @return the resource key name.
      */
     public String getName() {
         return name;
     }
 

 }

