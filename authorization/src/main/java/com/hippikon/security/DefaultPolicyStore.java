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

import org.apache.log4j.*;
 
 /**
  * The DefaultPolicyStore provides a default implementation 
  * of the {@link PolicyStore} interface that uses a tree-like
  * data structure to store and lookup ACLs for ProtectedResources.<p>
  *
  * All subclasses need to do is provide a {@link #load()} implementation
  * that populates the data structure from its own internal representation
  * (e.g., XML, database or flat file).<p>
  *
  * The data structure ties {@link ResourceAclList} objects together
  * that are place at the top of the tree.<p>
  * 
  * @author Dale Churchett
  * @version $Id: DefaultPolicyStore.java,v 1.3 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 abstract class DefaultPolicyStore extends PolicyStore {
 
     private static Logger log = Logger.getLogger("com.hippikon.security.DefaultPolicyStore");
 
     // this contains the top-level nodes and their respective   
     // entries in the policy store for each principal
     // in the form of resourceName->ResourceAclList key/value pairs
     // the caveat of this approach is that no duplicate objects
     // are allowed since we use a Hashtable
     //
     private Map<String, ResourceAclList> resourceAcls;
 
     // required for the PermsNavigator
     //
     protected Map<String, ResourceAclList> getResourceAcls() {
         if (resourceAcls == null) {
             resourceAcls = new HashMap<String, ResourceAclList>();
         }
         return resourceAcls;
     }
 
     /**
      * Loads the set ResourceAclList objects into the policy store.
      * When to call the load method is left to concrete implementations 
      * in order to implement a cache or lazy instantiation algorithms.<p>
      *
      * @exception PolicyStoreLoadException thrown if the resource ACLs could
      * not be loaded
      */
     protected abstract void load() throws PolicyStoreLoadException;
     
 
     /**
      * Adds a ResourceAclList to the PolicyStore. This must be called by
      * subclasses in order to initialize the resource ACLs data structure. 
      * This will most likely be performed in the {@link #load()} method.
      *
      * @param key the ProtectedResource name the list applies to
      * @param list a ResourceAclList object
      *
      * @pre key != null || ""
      * @pre list != null
      */
     protected synchronized void addResourceAclList(String key, ResourceAclList list) {
         if (resourceAcls == null) 
             resourceAcls = new HashMap<String, ResourceAclList>();
         log.debug(key + " being added to ResourceAclList as top-level node");
         if (key == null || key == "" || list == null) {
             log.error("NULL or empty object being added to ResourceAclList");
             return;
         }
         resourceAcls.put(key, list);
     }
 
 
     /**
      * Prints a '::' delimited resource path. Used for debugging only.
      */
     private void printResourcePath(List<String> resourcePath) {
         StringBuffer sb = new StringBuffer();
         for (ListIterator<String> x = resourcePath.listIterator(); x.hasNext();) {
             sb.append(x.next());
             sb.append("::");
         }
         log.debug("RESOURCE PATH: " + sb.toString().substring(0, (sb.toString().length() - 2)));
     }
 
 
     /**
      * Converts a LinkedList of ProtectedResource names into a List
      * of ResourceAclList objects
      */
     private List<ResourceAclList> getResourceAclListsForPathEntries(LinkedList<String> resNamePath)
     throws ResourceNotFoundException {
 
         // create a list to store the ResourceAclList defined by the resource path
         //
         List<ResourceAclList> resAclList = new ArrayList<ResourceAclList>();
 
         // init the current list so we can check for path entries
         //
         ResourceAclList currentList = (ResourceAclList)resourceAcls.get((String)resNamePath.getFirst());
         log.debug("Adding ResourceAclList to path: " + currentList.getResourceName());
         resAclList.add(currentList);
 
         // now traverse along the nested hierarchy
         // if any nested list is not found, a ResourceNotFoundException will be thrown
         // so we don't have to deal with that here
         //
         for (ListIterator<String> i = resNamePath.listIterator(1); i.hasNext();) {
             String resName = (String)i.next();
             ResourceAclList list = currentList.getNestedList(resName);
             log.debug("Adding ResourceAclList to path: " + list.getResourceName());
             resAclList.add(list);
             currentList = list;
         }
 
         return resAclList;
     }
 
     protected PermissionSet getPermissions(LinkedList<String> resNamePath, PolicyMediator mediator)
     throws ResourceNotFoundException {
         try {
             List<String> principals = mediator.getPrincipals();
             PermissionsPrincipalsStruct structure = _getPermissions(resNamePath, principals);
             PermissionSet perms = structure.perms;
             Map<String, PermissionSet> principalEntries = structure.principalPermsMap;
             return mediator.invokePolicyFinals(perms, principalEntries);
         } catch (Exception e) {
             throw new ResourceNotFoundException(e.getMessage());
         }
     }
 
     // here we toss away the principal entries
     //
     protected PermissionSet getPermissions(LinkedList<String> resNamePath, List<String> principals) 
     throws ResourceNotFoundException {
         return _getPermissions(resNamePath, principals).perms;
     }
     
     class PermissionsPrincipalsStruct {
    	 private PermissionSet perms;
    	 private Map<String, PermissionSet> principalPermsMap;
     }
 
     // first element is the permissions, 2nd element is the principalEntries 
     // map where key-value is the principal-perms value
     //
     private PermissionsPrincipalsStruct _getPermissions(LinkedList<String> resNamePath, List<String> principals) 
     throws ResourceNotFoundException {
 
    	 PermissionsPrincipalsStruct structure = new PermissionsPrincipalsStruct();
 
         printResourcePath(resNamePath);
 
         try {    
 
             // convert the list of ProtectedResource names (resource path) into
             // a list of respective ResourceAclList objects - we need this in 
             // order to lookup the user and role names defined for each 
             // ProtectedResource in the PolicyStore
             //
             List<ResourceAclList> resAclList = getResourceAclListsForPathEntries(resNamePath);
 
             // we use this to track overridden entries down the hierachy
             // this allows child entries to override those speified higher up
             // in the resource path
             //
             Map<String, PermissionSet> permEntries = new HashMap<String, PermissionSet> ();
             
             // we need to go backwards in order to support permission override
             //
             for (ListIterator<ResourceAclList> i = resAclList.listIterator(resAclList.size()); i.hasPrevious();) {
 
                 ResourceAclList aclList = (ResourceAclList)i.previous();
 
                 // work through principals
                 //
                 for (Iterator<String> j = principals.iterator(); j.hasNext();) {
 
                     String principal = (String)j.next();
 
                     // check to see if we found the ACL for the principal
                     // before we continue. If we don't find the ACL, one hasn't
                     // been defined for the ProtectedResource so we can't 
                     // strengthen the PermissionSet
                     //
                     ACL acl = aclList.getPrincipalACL(principal);
                     if (acl == null) continue;
 
                     // if we get this far, we can create the permission set 
                     // and add it to the list of permission set objects for
                     // the user
                     //
                     PermissionSet perms = new DefaultPermissionSet(acl.getPermsAsInt());
 
                     // this is the override method. Since we are traversing back through
                     // the list of ResourceAclList objects we will only include an 
                     // entry for a userType if it hasn't already been specified
                     //
                     if (!permEntries.containsKey(principal))
                         permEntries.put(principal, perms);
 
                 } // end principals
 
             } // end traversing back through the path
 
             // now add all the Permissions together
             //
             DefaultPermissionSet perms = new DefaultPermissionSet();
             Collection<PermissionSet> allPerms = permEntries.values();
             for (Iterator<PermissionSet> m = allPerms.iterator(); m.hasNext();) {
                 perms.addPermissions((PermissionSet)m.next());
             }
 
             structure.perms = perms;
             structure.principalPermsMap = permEntries;
 
             return structure;
 
         } catch (NullPointerException e) {
             throw new ResourceNotFoundException("Could not locate entry in PolicyStore");
         }
     }
 
 
 }

