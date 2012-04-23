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
  * The DefaultObjectPolicy class provides a mechanism to handle simple 
  * authorization based on the the roles assigned to a user. The role
  * permissions must be defined in a PolicyStore implementation.<p>
  *
  * The policy does not use any user principal logic and is 
  * provided as a catch-all policy for {@link ProtectedResource} objects that
  * have not been defined in the resource.policies file for a product.<p>
  *
  * @author Dale Churchett
  * @version $Id: DefaultObjectPolicy.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 public class DefaultObjectPolicy extends Policy {
 
     /**
      * Creates a new DefaultObjectPolicy to handle simple authorization
      * based on the roles the user has been assigned within a protected 
      * application.<p>
      *
      * @param res the ProtectedResource being accessed. This constructor
      * is required as part of the DefaultObjectPolicy contract.
      *
      * @param ctx the AuthorizationContext the ProtectedResource is being
      * accessed within.
      *
      * @exception IllegalAuthorizationException thrown if an illegal access attempt
      * was made by a user.
      *
      */
     public DefaultObjectPolicy(Object res, AuthorizationContext ctx) 
     throws IllegalAuthorizationException {
         super(res, ctx);
     }
 
 }

