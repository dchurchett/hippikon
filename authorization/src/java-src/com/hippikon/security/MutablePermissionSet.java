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
  * The MutablePermissionSet class provides an implementation
  * of the {@link PermissionSet} interface that may be manipulated
  * by {@link Policy} implementations.<p>
  *
  * This class has no public API and is used internally to 
  * implement authorization logic within the security 
  * authorization framework.<p>
  *
  * Policy subclasses may use this object during the 
  * {@link Policy#doFinal(PermissionSet)} method in order
  * to affect change prior to returning a PermissionSet
  * object back to the PermissionsFactory.<p>
  *
  * The only way a new instance of this class may be created
  * is through the {@link Policy#createMutablePermissionSet(PermissionSet)}
  * method that all Policy subclasses inherit.<p>
  *
  * @author Dale Churchett
  * @version $Id: MutablePermissionSet.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 public class MutablePermissionSet extends DefaultPermissionSet {
 
	private static final long serialVersionUID = -8927876207379712946L;

	/**
      * Creates a new MutablePermissionSet with initial
      * int value.
      *
      * @param flags an int value representing the binary
      * set of permission flags
      */
     protected MutablePermissionSet(int flags) {
         super(flags);
     }
 
     /**
      * Creates a new MutablePermissionSet instance with initial
      * permissions value. See {@link DefaultPermissionSet}.
      *
      * @param aclString a String represenation of a permission set
      */
     protected MutablePermissionSet(String aclString) {
         super(aclString);
     }
 
     /**
      * Creates a new MutablePermissionSet with initial
      * integer value based on the permissions of another
      * PermissionSet object.
      *
      * @param perms a PermissionSet object to deep-copy
      */
     protected MutablePermissionSet(PermissionSet perms) {
         super(perms);
     }
 
     /**
      * Creates a new MutablePermissionSet with no
      * flags enabled.
      */
     protected MutablePermissionSet() {
         super();
     }
 
     /**
      * Enables the CREATE flag of the PermissionSet
      */
     public void setCreateFlag() {
         flags |= CREATE_FLAG;
     }
 
     /**
      * Enables the READ flag of the PermissionSet
      */
     public void setReadFlag() {
         flags |= READ_FLAG;
     }
 
     /**
      * Enables the WRITE flag of the PermissionSet
      */
     public void setWriteFlag() {
         flags |= WRITE_FLAG;
     }
 
     /**
      * Enables the CONTROL flag of the PermissionSet
      */
     public void setControlFlag() {
         flags |= CONTROL_FLAG;
     }
 
     /**
      * Enables the DELETE flag of the PermissionSet
      */
     public void setDeleteFlag() {
         flags |= DELETE_FLAG;
     }
 
     /**
      * Disables the CREATE flag of the PermissionSet
      */
     public void unsetCreateFlag() {
         flags &= ~CREATE_FLAG;
     }
 
     /**
      * Disables the READ flag of the PermissionSet
      */
     public void unsetReadFlag() {
         flags &= ~READ_FLAG;
     }
 
     /**
      * Disables the WRITE flag of the PermissionSet
      */
     public void unsetWriteFlag() {
         flags &= ~WRITE_FLAG;
     }
 
     /**
      * Disables the CONTROL flag of the PermissionSet
      */
     public void unsetControlFlag() {
         flags &= ~CONTROL_FLAG;
     }
 
     /**
      * Disables the DELETE flag of the PermissionSet
      */
     public void unsetDeleteFlag() {
         flags &= ~DELETE_FLAG;
     }
 
     /**
      * A convenience method to disable all flags except for
      * the READ flag.
      */
     public void setReadOnly() {
         this.unsetCreateFlag();
         this.unsetWriteFlag();
         this.unsetControlFlag();
         this.unsetDeleteFlag();
     }
 
 
 }

