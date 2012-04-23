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
 
 import java.io.*;
 
 /**
  * The PermissionSet interface represents a set of flags (or an ACL entry) 
  * for a {@link ProtectedResource}. Each ProtectedResource may have many
  * PermissionSet instances representing the permissions assigned to 
  * different principals such as a role or user-type.<p>
  *
  * The interface defines a mechanism of combining multiple PermissionSet
  * objects that performs a logical OR operation to find the complete
  * set of permissions of a single user accessing a ProtectedResource 
  * within an {@link AuthorizationContext}. The user may play multiple roles 
  * or have some special association with the ProtectedResource 
  * (such as the instance creator).<p>
  * 
  * The user type logic is encapsulated in {@link Policy} implementations
  * that are bound to ProtectedResource objects at deploy time using a
  * <code>hippikon.product.[productID].resource.policies</code> file for the application.
  * PermissionSet rules must be defined in a {@link PolicyStore} for an 
  * application.<p>
  * 
  * Different mechanisms for different PermissionSet rules may vary, but
  * the preferred way is to use an XML file that conforms to the  
  * Hippikon DTD. See the Hippikon documentation for deatails.<p>
  *
  * To obtain the PermissionSet for a ProtectedResource, clients must 
  * use the Policy static method <p>
  *
  * <pre>
  * PermissionsFactory.getPermissions(ProtectedResource res, AuthorizationContext ctx)
  * </pre><p>
  *
  * Note there are no mutator methods defined for the interface. Application logic
  * may not change PermissionSet objects once returned from the 
  * {@link PermissionsFactory}. All authorization logic must be encapsulated in
  * a single package for an application and defined within the Policy
  * implementations for specialized ProtectedResource classes.<p>
  * 
  * <b>Semantics</b>
  *
  * The semantic meaning of each permission flag is as follows:<p>
  *
  * <b>canCreate() : </b> new instances of a ProtectedResource may be created. In cases
  * where no instances are ever created (an abstract class for example), the permission 
  * should not be enabled.<p>
  *
  * <b>canRead() :</b> the read-only public methods and attributes of a ProtectedResource
  * may be accessed. For most cases, this means the object can be retrieved and displayed
  * in a user interface. The instance may also participate in a remote transaction (XML/SOAP
  * for instance) provided the user granted READ initiates the operation.<p>
  *
  * <b>canWrite() : </b> the internal data of an existing ProtectedResource instance may
  * be modified. The internal data should not include any fields that store state information.<p>
  *
  * <b>canControl() : </b> changes to the internal state or life cycle of the object 
  * can be affected. Examples could include moving an object from IN_ACTIVE to 
  * ACTIVE through some operation provided on the ProtectedResource public interface.<p>
  *
  * <b>canDelete() : </b> an instance may be permanently deleted. In the case the object 
  * includes dependent objects through a composition association, all dependent objects 
  * recursively must also be deleted recursively (cascading delete). This permission also 
  * allows dependent objects to be deleted without the parent being affected 
  * (for example, deleting a note).<p>
  *
  * @author Dale Churchett
  * @version $Id: PermissionSet.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 public interface PermissionSet extends Serializable {
 
     /**
      * Returns true if the READ flag of the PermissionSet is enabled
      * @return true if READ enabled
      */
     public boolean canRead();
 
     /**
      * Returns true if the WRITE flag of the PermissionSet is enabled
      * @return true if WRITE enabled
      */
     public boolean canWrite();
 
     /**
      * Returns true if the CONTROL flag of the PermissionSet is enabled
      * @return true if CONTROL enabled
      */
     public boolean canControl();
 
     /**
      * Returns true if the DELETE flag of the PermissionSet is enabled
      * @return true if DELETE enabled
      */
     public boolean canDelete();
 
     /**
      * Returns true if the CREATE flag of the PermissionSet is enabled
      * @return true if CREATE enabled
      */
     public boolean canCreate();
 
 }

