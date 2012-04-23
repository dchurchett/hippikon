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
  * A default implementation of an Policy for an Activity
  *
  * @author Dale Churchett
  * @version $Id: ToDoItemPolicy.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 public class ToDoItemPolicy extends DefaultObjectPolicy {
 
     private ToDoItem activity;
 
     /**
      * Creates a new ActivityPolicy object
      */
     public ToDoItemPolicy(Object res, AuthorizationContext ctx)
     throws IllegalAuthorizationException {
         super(res, ctx);
         this.activity = (ToDoItem)res;
     }
 
     /**
      * Determines if the user specified in the AuthorizationContext 
      * is the user assigned to the activity ('assigned-user')
      */
     protected List<String> determineUserPrincipals() {
         List<String> list = new ArrayList<String>();
         if (ctx.getUserGUID().equals(activity.getUserGUID())) {
             list.add("assigned-user");
         }
         return list;
     }
 
     /**
      * The ActivityPolicy will mark an Activity as immutable if 
      * it has been completed.
      *
      * @return the PermissionSet object passed into the method by
      * the Security framework, modified depending on the state of
      * the Activity being checked.
      */
     protected PermissionSet doFinal(PermissionSet perms) {
 
         MutablePermissionSet mps = createMutablePermissionSet(perms);
 
         if (activity.getStatus() == ToDoItem.COMPLETED) {
             mps.setReadOnly();
         }
 
         return mps;
     }
 }

