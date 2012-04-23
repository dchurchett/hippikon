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
  * The ACL class represents an entry in a PolicyStore for a 
  * {@link ProtectedResource}. It is used as part of the internal
  * security package implementation and not exposed to clients 
  * as part of the public API.<p>
  *
  * The class provides a C-type struct to bind an integer
  * value of a PermissionSet to a name value of a principal.
  * For example, an entry under a role principal named "manager" may 
  * have the value of 0x08 (read-only).<p>
  *
  * The class is necessary to implement the ResourceAclList data structure 
  * of all ACLs for a ProtectedResource and store in memory for efficient
  * lookup.<p>
  *
  * The class could be made a private inner class of ResourceAclList.
  * Because it represents a key abstraction it has, therefore, been 
  * modelled as its own class.<p>
  *
  * @author Dale Churchett
  * @version $Id: ACL.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 class ACL {
 
     private String name;
     private int flags;
 
     /**
      * Creates a new ACL instance for a specific key and integer
      * representation of a PermissionSet
      * 
      * @param name the principal name of the ACL to map a integer representation of
      * a permission set to. This may not be null.
      * @param flags the integer representation of a permission set assigned
      * to the key
      *
      * @exception java.lang.IllegalArgumentException thrown if the name parameter   
      * is null or an empty string
      */
     ACL(String name, int flags) throws IllegalArgumentException {
         if (name == null || name.equals(""))
             throw new IllegalArgumentException("Name field may not be null or blank in ACL constructor");
         this.name = name;
         this.flags = flags;
     }
 
     /**
      * Returns the principal name of the ACL.
      * 
      * @return the name value of the ACL instance.
      */
     String getName() {
         return name;
     }
 
     /**
      * Returns the integer representation of the permission set assigned
      * to a name
      *
      * @returns an integer representation of a permission set
      */
     int getPermsAsInt() {
         return flags;
     }
 
 }

