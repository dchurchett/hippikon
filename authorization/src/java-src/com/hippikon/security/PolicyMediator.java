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
 
 import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;

import org.apache.log4j.Logger;
 
 /**
  * The PolicyMediator is a helper class that mediates interactions between 
  * the PermissionsFactory and the Policy implementations required to obtain
  * the data necessary in order to calculate the PermissionSet for a list of 
  * ProtectedResources. The mediator does this by invoking the callback 
  * methods of the policies, determineUserPrincipals() and doFinal(),
  * defined for each ProtectedResource in the list.<p>
  *
  * This class is based on the Mediator design pattern 
  * (ref: Design Patterns: Elements of Reusable Object Oriented Software)
  *
  * @author Dale Churchett
  * @version $Id: PolicyMediator.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 class PolicyMediator {
 
     private List<String> userTypes;
     private LinkedList<String> resourceList;
     private LinkedList<Policy> policyList;
     private AuthorizationContext ctx;
 
     private static Logger log = Logger.getLogger("com.hippikon.security.PolicyMediator");
 
     /**
      * Creates a new PolicyMediator instance
      *
      * @param resources a list of ProtectedResource objects ordered to
      * form a resource path. The path must match an entry in the PolicyStore
      * for the application
      * @param ctx the AuthorizationContext within which the access to the 
      * last ProtectedResource in the list is being accessed
      *
      * @exception PolicyStoreLoadException thrown if the PolicyStore
      * for the product being accessed within the AuthorizationContext
      * can not be loaded
      * @exception ProtectedResourceNamingException thrown if one of the
      * objects in the list does not implement the ProtectedResource
      * interface
      *
      */
     @SuppressWarnings("unchecked")
	PolicyMediator(List<Object> resources, AuthorizationContext ctx)
     throws PolicyStoreLoadException, ProtectedResourceNamingException {
 
         this.ctx = ctx;
         this.resourceList = new LinkedList<String>();
         this.userTypes = new ArrayList<String>();
         this.policyList = new LinkedList<Policy>();
 
         // we need to iterate through the ProtectedResource list to 
         // determine the user principals for the context - at the same time we
         // build the LinkedList of ProtectedResource names for efficiency
         //
         boolean foundClass = false;
         for (Iterator<Object> i = resources.iterator(); i.hasNext();) {
 
             // DJL - we need to extend this here.  What we will do is to check the resources iterator
             // to see if we are dealing with a Class object or a ProtectedResource object.  If we are 
             // dealing with a class, simply add this to the resourceList, but not to the policyList.
             // If we find a ProtectedResource after we find a class, we must throw an exception since
             // the protected resource MUST have access to the parent, and the class cannot be the parent.
             //
             Object obj = i.next();
             if (obj instanceof Class) {
                 String classResName = new ProtectedResourceWrapper((Class)obj).getResourceName();
                 resourceList.add(classResName);
                 foundClass = true;
                 continue;
             }
             if (foundClass) {
                 throw new ProtectedResourceNamingException("Protected Resource found after Class in the resources list");
             }
  
             // find out the resource name key that will match up with the policy store definition
             // if we are a Configurable object, use the getName() method, else use
             // we use getResourceName() on the class itself
             //
             String resourceName = null;
             if (obj instanceof Configurable) {
                 resourceName = ((Configurable)obj).getName();
             } else {
                 resourceName = new ProtectedResourceWrapper(obj).getResourceName();
             }
             resourceList.add(resourceName);
 
             // get the correct Policy for the ProtectedResource and maintain 
             // a reference so we can invoke the doFinalPermissions(perms) of each
             //
             Policy policy = PolicyBroker.getPolicy(obj, ctx);
             policyList.add(policy);
 
             logPolicyLoadEvent(policy, resourceName);
 
             List<String> resourceUserTypes = policy.determineUserPrincipals();
 
             // only add unique user types - may make sense to use a Map here
             //
             for (Iterator<String> j = resourceUserTypes.iterator(); j.hasNext();) {
                 String userType = (String)j.next();
                 if (!userTypes.contains(userType)) {
                     userTypes.add(userType);
                 }
             }
 
         } // end resource loop
 
         // now set the complete list for the context of the user
         //
         ctx.setUserPrincipals(userTypes);
     }
 
 
     /**
      * Returns all user types defined for the resource path passed in
      * as a List object in the constructor. These user types represent
      * all possible ownership entries in the PolicyStore.
      */
     private List<String> getUserTypes() {
         return userTypes;
     }
 
 
     /**
      * Returns all principals that may be used to determine permissions
      * for the resource path defined in the PolicyStore for the appliction
      * being accessed.
      *
      * The principals include user principals (determined from the Policy implementations
      * for each ProtectedResource, plus the role principals assigned to a user for the 
      * product being accessed (determined from the AuthorizationContext).
      *
      * It is important to note that the principal list does not necessarily
      * match all entries defined in the PolicyStore for each ProtectedResource, but
      * those that <b>may</b> be defined. Just because a user has been assigned the 
      * role of 'manager' does not mean that principal must be defined in the 
      * PolicyStore for each ProtectedResource.
      *
      */
     List<String> getPrincipals() {
         List<String> principals = new ArrayList<String>();
         principals.addAll(getUserTypes());
         principals.addAll(ctx.getUserRoles());
         if (getUserTypes().size() != 0) {
             principals.addAll(ctx.getUserGroups());
         }
         return principals;
     }
 
 
     /**
      * Returns a LinkedList of String objects representing the resource path
      * created from the list of ProtectedResource objects passed into the 
      * constructor
      */
     LinkedList<String> getResourceList() {
         return resourceList;
     }
 
     /**
      * Returns the PermissionSet once all the policy objects 
      * have been given the chance to perform their final 
      * permissions check.
      * 
      * @param perms the PermissionSet object whose values have been determine
      * through the PolicyStore configuration object.
      * @param principalAcls a Map structure where the key-value elements are
      * the principal String objects and their respective PermissionSet objects. These
      * are made available to Policy implementations in case dynamic logic is required
      * and policy implementions need to know how the permission set coming into the doFinal()
      * methods were determined (for instance, implement a different permissions inheritance
      * algorithm).
      *
      * @exception IllegalAuthorizationException thrown if the PermissionSet returned from
      * any of the doFinal() methods is null
      */
     PermissionSet invokePolicyFinals(PermissionSet perms, Map<String, PermissionSet> principalAcls)
     throws IllegalAuthorizationException {
 
         PermissionSet newPerms = new DefaultPermissionSet(perms);
         for (ListIterator<Policy> i = policyList.listIterator(policyList.size()); i.hasPrevious();) {
             Policy policy = (Policy)i.previous();
 
             // make sure we make the user principals across the scope of the authorization request
             // available to each policy prior to invoking the doFinal methods
             // and also the principal/permission-set key/values so each policy has some insight
             // into how the permissions were found from the PolicyStore configuration
             //
             policy.setUserPrincipals(getUserTypes());
             policy.setPrincipalAcls(principalAcls);
             newPerms = policy.doFinal(newPerms);
             if (newPerms == null) {
                 throw new IllegalAuthorizationException("NULL PermissionSet returned from doFinal invoked " +
                                                         "on Policy class: " + policy.getClass().getName());
             }
         }
         return newPerms;
     }
 
     /**
      * Logs a debug event when a policy is loaded for a ProtectedResource
      */
     private void logPolicyLoadEvent(Policy policy, String resourceName) {
         log.debug("Policy class loaded:" + policy.getClass().getName() + " for ProtectedResource: " + resourceName);
     }
 
 }

