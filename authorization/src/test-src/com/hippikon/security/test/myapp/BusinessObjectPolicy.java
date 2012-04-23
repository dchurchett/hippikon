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
 package com.hippikon.security.test.myapp;
 
 import com.hippikon.security.*;
 import java.util.*;
 
 /**
  * The BusinessObjectPolicy implementation provides logic that 
  * strengthens the user {@link PermissionSet} based on whether
  * the user accessing a BusinessObject is the creator.<p>
  *
  * If this is true, the user is assigned the default permissions
  * of READ, WRITE and CONTROL.<p>
  *
  * @author <a href="mailto:dale@hippikon.com">Dale Churchett</a>
  * @version $Id: BusinessObjectPolicy.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  */
 
 public class BusinessObjectPolicy extends Policy {
 
     private BusinessObject obj;
     private AuthorizationContext ctx;
 
     /**
      * Creates a new BusinessObjectPolicy
      *
      * @param res the ProtectedResource being accessed. This constructor
      * is required as part of the DefaultObjectPolicy contract.
      *
      * @exception IllegalAuthorizationException thrown if an illegal access attempt
      * was made by a user, or if the ProtectedResource does not implement
      * the BusinessObject interface. In this case, a subversive access may
      * have been attempted.
      *
      * @exception ClassCastException thrown if the ProtectedResource
      * could not be cast to a BusinessObject
      */
     public BusinessObjectPolicy(Object res, AuthorizationContext ctx) 
     throws IllegalAuthorizationException, ClassCastException {
         super(res, ctx);
         this.obj = (BusinessObject)res;
     }
 
     /**
      * Determines if the user attempting to access a BusinessObject
      * is the 'the-creator'.
      */
     protected List<String> determineUserPrincipals() {
         List<String> list = new ArrayList<String>();
         if (ctx.getUserGUID().equals(obj.getCreatorGUID())) {
             list.add("the-creator");
         }
         return list;
     }
 }

