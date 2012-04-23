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
 
 import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
 
 /**
  * The AuthorizationContext provides a place holder for information retrieved
  * after a user of a application has been authentication. Authentication is
  * deferred to a different subsystem and is not provided as part of the Hippikon
  * API. In fact, the details of authentication are completely decoupled, and any
  * authentication system can be used.<p>
  *
  * In order to hook into the Hippikon authorization framework, a post condition
  * resulting from a successful authentication should be that a valid AuthorizationContext
  * object has been created, which can then be used to obtain a {@link PermissionSet}
  * that governs access to a {@link ProtectedResource}.<p>
  *
  * The information within the context object must be passed to every authorization
  * request in order to obtain the PermissionSet. Subclasses should consider implementing 
  * their own persistence mechanism to avoid potentially expensive calls on each 
  * authorization request e.g., storing roles in an Cookie for web based systems.<p>
  *
  * The context object also provides a Check Point (ref: Yoder) for each user access 
  * attempt before any permission checking is performed. If the accountID, userGUID or
  * productID attributes are not available or deemed invalid, an {@link IllegalAuthorizationException}
  * must be thrown.<p>
  *
  * @author Dale Churchett
  * @version $Id: AuthorizationContext.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 public abstract class AuthorizationContext implements java.io.Serializable {
 
	private static final long serialVersionUID = -6057763419469211616L;

	/**
      * Returns the identifier of the product being accessed by the
      * user. The combination of the productID and the accountID is
      * used to qualify roles that are product-specific.
      *
      * @return the identifier of the product being accessed
      *
      * @pre the user has been authenticated
      * @post getProductID() != null || ""
      */
     public abstract String getProductID();
 
     /**
      * Returns the identifier of the account the user belongs to.
      *
      * @return the identifer of the account the user belongs to
      *
      * @pre the user has been authenticated
      * @post getAccountID() != null || ""
      */
     public abstract String getAccountID();
 
     /**
      * Returns the unique identifer of the authenticated user 
      * accessing a ProtectedResource.
      *
      * @return the unique identifer of the user
      */
     public abstract String getUserGUID();
 
     /**
      * Returns a List roles assigned to the authenticated user as Strings
      * in the context of the product being accessed. Each product
      * must defined at least one role that users may be assigned, plus
      * application specific roles used by the business logic. 
      *
      * @return the list of roles assigned to the user in the context of 
      * the product being accessed.
      *
      * @pre the user has been authenticated
      * @post getUserRoles().length >= 1
      */
     public abstract List<String> getUserRoles();
 
     /**
      * Determines if the user is assigned to the input role.
      *
      * @param role the role to be tested.
      * @return true if the user is assigned to the role, false otherwise.
      * @pre the user has been authenticated.
      */
     public abstract boolean isAssignedToRole(String role);
 
     /**
      * Returns a List of subscriptions available to the authenticated user 
      * as Strings.
      *
      * @return the list of subscriptions available to the user.
      *
      * @pre the user has been authenticated
      * @post getSubscriptions().length >= 1
      */
     public abstract List<String> getSubscriptions();
 
     /**
      * Gets the Locale to be used.  If no locale was determined, returns null.
      *
      * @return the locale, or null if no locale specified.
      */
     public abstract Locale getLocale();
 
     /**
      * Gets the TimeZone to be used.  If no
      * timezone was determined, returns the timeZone for GMT.
      *
      * @return the timeZone.
      */
     public abstract TimeZone getTimeZone();
 
     /**
      * Sets the list of user principals determined by
      * the Policy callbacks for each ProtectedResource
      * being accessed.
      *
      * @param principals a List of String objects representing
      * the user principals determined by Policy classes mapped
      * to ProtectedResource objects being accessed.
      */
     protected abstract void setUserPrincipals(List<String> principals);
 
     /**
      * Returns a List groups assigned to the authenticated user as Strings
      * in the context of the product being accessed. 
      *
      * @return the list of groups assigned to the user in the context of 
      * the product being accessed.
      *
      * @pre the user has been authenticated
      * @post getUserGroups() != 0
      */
     public abstract List<String> getUserGroups();
 
     /**
      * Returns the list of all principals of a user 
      * determined through a combination of user roles, groups 
      * and associations with the ProtectedResources being
      * accessed.<p>
      *
      * This method is not made public because there is
      * no guarentee when this value will be set by the
      * authorization framework.
      */
     protected abstract List<String> getPrincipals();
 
     /**
      * Sets the list of ProtectedResource names being accessed
      * within the AuthorizationContext. This method is provided
      * to pass through the complete authorization context
      * to policy implementations only.<p>
      *
      * It is not made public since the authorization framework
      * does not guarentee when the resource path list will
      * be set.
      *
      * @param resources a List of String objects representing
      * the hierachy of ProtectedResource objects being accessed.
      * The Strings match the {@link ProtectedResource#getResourceName()}
      * return values. 
      */
     protected abstract void setResourcePath(List<String> resources);
 
     /**
      * Returns the List of names of each ProtectedResource
      * being accessed by the client.
      *
      * @return a List of String objects
      */
     protected abstract List<String> getResourcePath();
 
 }

