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
  * The Policy abstract class provides a simple mechanism for 
  * specializing security logic for a {@link ProtectedResource}
  * at runtime.<p>
  * 
  * Once a user has been authenticated, a user may need access to different
  * resources within an application. Each application may provide its own
  * authorization policy implementations to serve its specific needs. The 
  * authorization API therefore provides a white-box framework, where the hooks
  * for extensibility and specialization are in the form of {@link Policy}
  * implementations.<p>
  * 
  * Where specialized logic is not required the {@link DefaultObjectPolicy}
  * class will be automatically invoked instead.<p>
  *
  * The methods defined in this class provide some toolkit methods for 
  * Policy developers in order to create and manipulate PermissionSet 
  * objects in the {@link #doFinal(PermissionSet perms)} methods.<p>
  * 
  * These methods proxy the DefaultPermissionSet and MutablePermissionSet constructors
  * in order to prevent clients from creating their own PermissionSet objects
  * and possibly by-passing the authorization framework altogether. The trade-off
  * with this approach is that the Policy class seems in-cohesive and Policy developers
  * must know about the implementation. The fact that clients are prevented from 
  * by-passing the framework seems a reasonable trade-off.<p>
  *
  * This is another reason the authorization framework is considered a 
  * white-box framework.<p>
  *
  * @author Dale Churchett
  * @version $Id: Policy.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 public abstract class Policy {
 
     // stores the user principals for the scope of the authorization check
     //
     private List<String> userPrincipals;
 
     // stores the context of how the final permissions were obtained
     // from the PolicyStore definitions
     //
     private Map<String, PermissionSet> principalAcls;
 
     /**
      * The {@link ProtectedResource} instance used to determine 
      * user principals and specialized authorization logic. Policy
      * implementations will need to narrow-cast the object to the expected
      * type.
      */
     protected Object res;
 
     /**
      * The {@link AuthorizationContext} within which the client access to
      * a {@link ProtectedResource} is being made
      */
     protected AuthorizationContext ctx;
 
     /**
      * Creates a new Policy object to handle specialized permissions
      * to be defined for a ProtectedResource within an 
      * AuthorizationContext.
      *
      * Subclasses must provide a constructor matching the parameters
      * in this method for dynamic constructor chaining to work.
      * 
      * @param res a ProtectedResource being accessed
      * @param ctx the AuthorizationContext within which the 
      * ProtectedResource is being accessed
      */
     public Policy(Object res, AuthorizationContext ctx) {
         this.res = res;
         this.ctx = ctx;
     }
 
     /**
      * Returns a list of user principals to match with
      * entries in a {@link PolicyStore} for a {@link ProtectedResource}
      * This method should be implemented by specialized policies that 
      * need to apply user permissions based on their association with
      * an ProtectedResource object.<p>
      *
      * This method must guarentee to return a list object that
      * is non-null (i.e., emtpy)
      *
      * @return a list of user types associated with a ProtectedResource
      *
      * @post determineUserPrincipals() != null
      */
     protected List<String> determineUserPrincipals() {
         return new ArrayList<String>();
     }
 
     /**
      * Allows subclasses the opportunity to perform final logic on the PermissionSet 
      * before returning to the client.<p>
      *
      * Objects that need to have flags unset due to internal state or
      * application logic can override the permissions calculated
      * using the rules in the {@link PolicyStore}. This keeps
      * business logic in one place while still maintain a separation
      * of concerns from the PolicyStore.
      *
      * The policy may also check the PermissionSet flags as a last
      * Check Point (Yoder) to ensure any minimal guarentees are
      * in place.<p>
      *
      * The default implementation does not affect the PermissionSet
      * passed in as a method parameter i.e., what comes in goes out.<p>
      *
      * @return the final PermissionSet to return to the client
      *
      * @post finalPermissionCheck() != null
      */
     protected PermissionSet doFinal(PermissionSet perms) {
         return perms;
     }
 
     /**
      * Returns a new {@link MutablePermissionSet} instance that may be used by 
      * Policy subclasses in their doFinal() methods. This is the only way
      * the PermissionSet obtained from a PolicyStore may be altered and ensures
      * authorization logic is encapsulated in Policy implementations only.
      *
      * @param perms a PermissionSet object that needs the permissions 
      * altering in some way, most commonly for unsetting permission flags   
      * due to some specialized authorization logic
      *
      * @return a MutablePermissionSet instance initialized with the value of
      * an existing PermissionSet object
      */
     protected final MutablePermissionSet createMutablePermissionSet(PermissionSet perms) {
         return new MutablePermissionSet(perms);
     }
 
 
     /**
      * Returns a new {@link DefaultPermissionSet} instance that may be used by
      * Policy subclasses in their doFinal() methods. This is the only way
      * classes outside of the <code>com.hippikon.security</code> package may
      * create new PermissionSet objects and is provided for Policy 
      * developers and internal security implementation only.<p>
      *
      * @param int an integer value representing a permission set. This will 
      * be obtained from a PolicyStore.
      * 
      * @return a DefaultPermissionSet instance initialized with the
      * permission flags represented by the integer method argument
      *
      */
     protected final DefaultPermissionSet createDefaultPermissionSet(int flags) {
         return new DefaultPermissionSet(flags);
     }
 
     /**
      * Returns the list of {@link ProtectedResource} names that represent
      * the resource path being accessed. The <code>getResourcePath()</code>
      * method is provided to allow Policy implementations to examine 
      * the context the Policy callbacks are being called within
      * in order to provide fine-grained authorization logic.
      *
      * @return a List of String objects that match the 
      * <code>getResourceName()</code> methods of each ProtectedResourc  
      * being accessed.
      */
     protected List<String> getResourcePathInContext() {
         return ctx.getResourcePath();
     }
 
     /**
      * Returns the user principals determined within the scope of the current
      * authorization request. The security framework gurantees to set this list
      * prior to invoking all the doFinal() methods, thus making the user principle
      * list available to policy plug-in classes if required.
      *
      * @return a List of String objects equal to the user principals determined
      * for the scope of the authorization request. May not be null.
      */
     protected final List<String> getUserPrincipals() {
         if (userPrincipals == null)
             userPrincipals = new ArrayList<String>();
         return userPrincipals;
     }
 
     /**
      * Sets the user principals determined for the scope of the authorization check.
      *
      * @param principals a List of String objects representing the user principals
      * determined for in the scope of the authorization request
      */
     protected final void setUserPrincipals(List<String> principals) {
         this.userPrincipals = principals;
     }
 
     /**
      * Returns the principle/permission set key/values that were determined
      * by the framework based on entries in the PolicyStore configuration from
      * the product being accessed. The structure is made available to subclasses
      * who may need to implement their own inheritance of permissions algorithms and
      * therefore will need to know how the PermissionSet being passed into each 
      * doFinal() method was determined.
      *
      * @return a Map of String-PermissionSet objects
      */
     protected final Map<String, PermissionSet> getPrincipalAcls() {
         return principalAcls;
     }
 
     /**
      * Sets the principle/permission set key/values that were determined
      * by the security framework from the PolicyStore configuration.
      */
     protected final void setPrincipalAcls(Map<String, PermissionSet> principalAcls) {
         this.principalAcls = principalAcls;
     }
 }

