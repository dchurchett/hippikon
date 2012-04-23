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
 
import java.util.*;
 
 /**
  * The PolicyStore represents a list of permissions defined for 
  * {@link ProtectedResource} objects hosted within a product.<p>
  *
  * A policy store entry must list each ProtectedResource class
  * and may define permissions for principals such as the roles a user 
  * may be assigned, or a association between a specific user and 
  * an instance of a ProtectedResource.<p>
  *
  * @author Dale Churchett
  * @version $Id: PolicyStore.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 public abstract class PolicyStore {
 
     /**
      * Returns the PermissionSet for a list of ProtectedResource entries
      * in the PolicyStore within an AuthorizationContext. The list represents
      * the object hierachy described in the store, which should mirror the 
      * domain class model of the application hosting the ProtectedResource
      * objects.
      *
      * @param resourcePath a LinkedList of names representing the tree hierachy
      * of one or more ProtectedResource entries in the PolicyStore
      * @param principals the list of principals of a user as determined by 
      * the Policy implementations bound to each ProtectedResource in the list. These
      * may also include the roles assigned to a user within the product hosting
      * the resources being accessed.
      *
      * @return the complete PermissionSet of the access attempt within the 
      * context of the object hierachy and AuthorizationContext
      *
      * @exception ResourceNotFoundException thrown if the resourcePath
      * is not defined in the {@link PolicyStore} for the {@link AuthorizationContext}
      *
      * @post getPermissions(resourcePath, ctx) != null
      */
     protected abstract PermissionSet getPermissions(LinkedList<String> resourcePath, List<String> principals)
     throws ResourceNotFoundException;
 
     /**
      * Returns the PermissionSet for a list of ProtectedResources, and ensures the security
      * Policy plugin classes are invoked in the correct order.
      *
      * @param resourcePath a LinkedList of names representing the tree hierachy
      * of one or more ProtectedResource entries in the PolicyStore
      * @param the PolicyMediator responsible for controlling interaction between the Policy implementations
      * and the framework. The mediator instance must be created within the scope of the authorization
      * request.
      *
      * @exception ResourceNotFoundException thrown if the resourcePath
      * is not defined in the {@link PolicyStore} for the {@link AuthorizationContext}
      */
     protected abstract PermissionSet getPermissions(LinkedList<String> resourcePath, PolicyMediator mediator)
     throws ResourceNotFoundException;
     
     
     /**
      * Returns a sorted List of the unique principals defined
      * in a policy store implementation.
      *
      * @return a List of sorted String objects
      */
     public abstract List<String> getDefinedPrincipals();
 
 
 }

