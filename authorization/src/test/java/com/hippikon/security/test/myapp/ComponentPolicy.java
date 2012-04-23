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
 
 import java.util.*;
import com.hippikon.security.*;

 
 /**
  * The PartPolicy class provides specialized authorization logic
  * for the Vendor module. It is provided as an example
  * implementation only.
  *
  * @author Dale Churchett
  * @version $Id: ComponentPolicy.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 public class ComponentPolicy extends DefaultObjectPolicy {
 
     @SuppressWarnings("unused")
	private Component part;
     @SuppressWarnings("unused")
	private Project project;
 
     public ComponentPolicy(Object res, AuthorizationContext ctx)
     throws IllegalAuthorizationException {
         super(res, ctx);
         this.part = (Component)res;
         this.project = new Project();
     }
 
     /**
      * The PartPolicy needs to determine if a user within an
      * AuthorizationContext is 'the-buyer'
      */
     protected List<String> determineUserPrincipals() {
         return new ArrayList<String>();
     }
 
     /**
      * 
      */
     protected PermissionSet doFinal(PermissionSet perms) {
         /* provided to ensure no Vendors can create Issues
            once the purchasing activity is completed
         if (purchaseActivity.getState() == Activity.COMPLETED) {
             MutablePermissionSet mps = createMutablePermissionSet(perms);
             mps.setReadOnly();
             return perms;
         } else {
             return perms;
         }
         */
         return perms;
 
     }
 
 }

