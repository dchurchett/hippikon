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
  * The DefaultAuthorizationContext provides a basic implementation of the
  * {@link AuthorizationContext} interface. New instances should be created
  * by the authorization subsystem upon a successful authentication. The 
  * authentication subsystem must therefore guarantee that the userGUID and accountID
  * of the authenticated user is available to the authorization subsystem.<p>
  *
  * In distributed applications the information may be passed to a Mediator 
  * (ref: Design Patterns: Elements of Reusable Object Oriented Software) 
  * that is responsible for making the AuthorizationContext object available 
  * to a client application.<p>
  *
  * For example, in an HTTP web based application this information may be available on the
  * HttpRequest header, and a subclass to examine the HttpRequest may be named 
  * HttpAuthorizationContext.<p>
  *
  * @author Dale Churchett
  * @version $Id: DefaultAuthorizationContext.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 public class DefaultAuthorizationContext extends AuthorizationContext {
 
	private static final long serialVersionUID = 817637745066088044L;

	/** The account ID to which the user making the request belongs */
     protected String accountID;
 
     /** The product ID being accessed  */
     protected String productID;
 
     /** The identifier of the user making the access request */
     protected String userGUID;
 
     /** The list of enabled subscriptions for the user's account ID */
     protected List<String> subscriptions;
 
     /** The locale of the user making the access request */
     protected Locale locale;
 
     /** The time zone of the user making the access request */
     protected TimeZone timeZone;
 
     /** The list of roles assigned to the user for the product being accessed */
     protected List<String> userRoles;
 
     /** The list of groups assigned to the user for the product being accessed */
     protected List<String> userGroups;
 
     /** The complete list of principals determined at runtime */
     protected List<String> principals;
 
     /** The List of ProtectedResource names being accessed */
     protected List<String> resources;
 
     /**
      * The default constructor required for sub classing
      */
     protected DefaultAuthorizationContext() {
         this.principals = new ArrayList<String>();
         this.resources = new ArrayList<String>();
     }
 
     /**
      * Creates a new DefaultAuthorizationContext object post-successful 
      * authentication.<p>
      *
      * Subclasses could pull this information from a database, subsystem or 
      * HTTP Requst headers/cookies. All checking for valid authentication
      * information must be performed in the constructor prior to any permissions
      * checking.
      *
      * @param accountID the identifier of the account the user belongs to [mandatory]
      * @param productID the identifier of the product or application being access [mandatory]
      * @param userGUID the identifier of the authenticated user [mandatory]
      * @param userRoles a List of String role names assigned to the user for the product being
      * accessed. The user must have been assigned <b>at least one role before they 
      * can be authorized to any resource</b>
      *
      * @exception IllegalAuthorizationException thrown if any mandatory fields are null, blank
      * or invalid within the system, or no product subscriptions exist 
      */
     public DefaultAuthorizationContext(String accountID, String productID, List<String> subscriptions, String userGUID, 
                                        List<String> userRoles) 
     throws IllegalAuthorizationException {
         this(accountID, productID, subscriptions, userGUID, userRoles, new ArrayList<String>());
     }
 
     /**
      * Creates a new DefaultAuthorizationContext object post-successful 
      * authentication.<p>
      *
      * Subclasses could pull this information from a database, subsystem or 
      * HTTP Request headers/cookies. All checking for valid authentication
      * information must be performed in the constructor prior to any permissions
      * checking.
      *
      * @param accountID the identifier of the account the user belongs to [mandatory]
      * @param productID the identifier of the product or application being access [mandatory]
      * @param userGUID the identifier of the authenticated user [mandatory]
      * @param userRoles a List of String role names assigned to the user for the product being
      * accessed. The user must have been assigned <b>at least one role before they 
      * can be authorized to any resource</b>
      * @param userGroups a List of String group names assigned to the user for the product being
      * accessed.  The user may or may not have been assigned to any groups.
      *
      * @exception IllegalAuthorizationException thrown if any mandatory fields are null, blank
      * or invalid within the system, or no product subscriptions exist 
      */
     public DefaultAuthorizationContext(String accountID, String productID, List<String> subscriptions, String userGUID, 
                                        List<String> userRoles, List<String> userGroups) 
     throws IllegalAuthorizationException {
 
         this.accountID = accountID;
         this.productID = productID;
         this.subscriptions = subscriptions;
         this.userGUID = userGUID;
         this.userRoles = userRoles;
         this.userGroups = userGroups;
         this.principals = new ArrayList<String>();
 
 
         // enforce the business rules here
         // these should include
         //
         // the user must have been assigned at least one role
         // the user account has not been disabled
         // the users account must have a subscription to the product being accessed
         // the users account subscription to the product being accessed is enabled
         //
         if (subscriptions.size() == 0 || this.userRoles.size() == 0)
             throw new IllegalAuthorizationException("User has no role assignments.");
 
         if (!subscriptions.contains(productID))
             throw new IllegalAuthorizationException("No subscription exists for the product being accessed");
             
      }
 
     public String getProductID() {
         return productID;
     }
 
     /**
      * Set the product ID so that we can change authorization contexts as needed.
      *
      * @param productID the new product ID to query.
      */
     public void setProductID(String productID) {
         this.productID = productID;
     }
 
     public String getAccountID() {
         return accountID;
     }
 
     public String getUserGUID() {
         return userGUID;
     }
 
     public List<String> getUserRoles() {
         return userRoles;
     }
 
     public boolean isAssignedToRole(String role) {
         if ((getUserRoles() == null) || (getUserRoles().size() == 0) || (role == null)) {
             return false;
         }
         Iterator<String> i = getUserRoles().iterator();
         while (i.hasNext()) {
             if (role.compareToIgnoreCase(i.next().toString()) == 0) {
                 return true;
             }
         }
         return false;
     }
 
     public List<String> getUserGroups() {
         return userGroups;
     }
 
     public List<String> getSubscriptions() {
         return subscriptions;
     }
 
     public Locale getLocale() {
         return locale;
     }
 
     public TimeZone getTimeZone() {
         return timeZone;
     }
 
     protected void setUserPrincipals(List<String> principals) {
         this.principals = principals;
     }
 
     protected List<String> getPrincipals() {
         List<String> allPrincipals = new ArrayList<String>();
         allPrincipals.addAll(getUserRoles());
         allPrincipals.addAll(principals);
         allPrincipals.addAll(getUserGroups());
         return allPrincipals;
     }
 
     protected void setResourcePath(List<String> resources) {
         this.resources = resources;
     }
 
     public List<String> getResourcePath() {
         return resources;
     }
 
 }

