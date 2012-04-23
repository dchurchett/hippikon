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
 
 import org.apache.log4j.*;
 import java.util.*;
 
 /**
  * The ResourceAclList class provides a data structure to store {@link ACL}
  * objects for a {@link ProtectedResource}. This is used internally by the 
  * authorization API and not exposed to clients in the public API.<p>
  *
  * The general data structure is defined below:<p>
  *
  *<pre>
  * resourceAclList->contains principal/acl permission values
  *                ->contains nested ResourceAclList objects
  *</pre>
  *
  * When an authorization request is made to the framework through the
  * {@link PermissionsFactory} class a List of ProtectedResource objects
  * may be passed in as a method parameter. This list represents one object
  * hierarchy defined for an application.<p>
  *
  * ProtectedResource objects may contain other ProtectedResource objects, each
  * with permissions that may vary depending on their position in different
  * hierarchies. The ResourceAclList class provides this mapping for an 
  * application. {@link PolicyStore} implementations may create a static
  * data structure or load from a persistant store. See {@link XMLPolicyStore}
  * for an XML based rule definition mechanism.<p>
  *
  * Each entry in the ResourceAclList maps principal entries (such as user-types
  * and roles) to ACL objects (which are C-like structs containing the integer 
  * permission value) for a name. The list is used to retrieve the correct 
  * permission set integer value for a given acl entry from either the 
  * principals hashtables.<p>
  *
  * The list simulates a multi-dimensional array while providing a convenient 
  * API for implementation classes.<p>
  *
  * @author Dale Churchett
  * @version $Id: ResourceAclList.java,v 1.5 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 class ResourceAclList {
 
     private String resName;
     private Map<String, ResourceAclList> childList;
     private Map<String, ACL> principalAclList;
 
     private static Logger log = Logger.getLogger("com.hippikon.security.ResourceAclList");
 
     /**
      * Creates a new ResourceAclList object to contain {@link ACL} object   
      * for a {@link ProtectedResource}
      *
      * @param resourceName the identifier of a {@link ProtectedResource}. This
      * should match the value of <code>getResourceName()</code>
      */
     ResourceAclList(String resourceName) {
         this.resName = resourceName;
         this.principalAclList = new HashMap<String, ACL>();
         this.childList = new HashMap<String, ResourceAclList>();
     }
 
     /**
      * Adds a nested ResourceAclList object that
      * inherits acls from its parent. The list
      * may override ACLs already defined.
      *
      * @param list the ResourceAclList to add as a child
      */
     void addNestedList(ResourceAclList list) {
         log.debug("Adding nested list [" + list.getResourceName() + "] to " + resName);
         if (list != null)
             childList.put(list.getResourceName(), list); 
     }
 
 
     /**
      * Returns true if a nested list exists for a specified
      * ProtectedResource name
      *
      * @return true if the resource list contains a nested list
      * for a specified resource name
      */
     boolean containsNestedList(String resourceName) {
         return (childList.containsKey(resourceName)) ? true : false;
     }
 
 
     /**
      * Returns a ResourceAclList object for a specified resource name
      * that is a child of the ResourceAclList.
      *
      * @return a nested ResourceAclList containing ACL entries for a specified
      * ProtectedResource. This method guarentees not to return a NULL object
      * 
      * @exception ResourceNotFoundException thrown if the nested child does not
      * exist
      * 
      * @post getNestedList(resourceName) != null
      */
     ResourceAclList getNestedList(String resourceName) throws ResourceNotFoundException {
     
         if (!containsNestedList(resourceName))
             throw new ResourceNotFoundException("Nested ResourceAclList not found for " + resourceName);
 
         ResourceAclList nestedList = (ResourceAclList)childList.get(resourceName);
         if (nestedList == null)
             throw new ResourceNotFoundException("NULL object found for nested list");
 
         return nestedList;
     }
 
     /**
      * Returns a List of all nested ResourceAclList objects
      */
     Map<String, ResourceAclList> getNestedList() {
         return childList;
     }
 
     /**
      * Returns a Collection of ACL objects.
      */
     Collection<ACL> getAcls() {
         return principalAclList.values();
     }
     
 
     /**
      * Returns the ProtectedResource name
      */
     String getResourceName() {
         return resName;
     }
 
     /**
      * Adds a principal {@link ACL} to the ResourceAclList. The ACL may not
      * be null and the <code>getName()</code> method must return
      * a unique name.
      *
      * @param acl the ACL instance to add to the ResourceAclList
      */
     void addPrincipalACL(ACL acl) {
         if (acl == null) return;
         principalAclList.put(acl.getName(), acl);
     }
 
     /**
      * Returns the {@link ACL} entry for a named principal. 
      *
      * @param principal the name of the principal to return the ACL for
      * @return the ACL stored in the ResourceAclList for a ProtectedResource or
      * NULL if the ACL entry could not be found. We used to throw 
      * an ACLNotFoundException but this turned out to be a performance
      * bottleneck due to the fillStackTrace() method
      */
     ACL getPrincipalACL(String principal) {
 
         ACL acl = (ACL)principalAclList.get(principal);
 
         if (acl == null)
                 log.debug("Principal ACL [" + principal + "] not defined for resource: " + resName);
 
         return acl;
     }
     
     /**
      * Removes all principal ACL entries for this resource
      */
     void clearPrincipalACLs() {
         principalAclList = new HashMap<String, ACL>();
     }
     
     // renames the resource this resourceAclList is associated with
     //
     void renameTo(String newName) {
         this.resName = newName;
     }
 
     /**
      * Returns the name of the protected resource this structure contains the ACLs for
      */
     public String toString() {
         return getResourceName();
     }
 
 }

