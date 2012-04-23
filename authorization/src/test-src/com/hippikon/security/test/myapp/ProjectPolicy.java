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
 
 import java.util.ArrayList;
import java.util.List;

import com.hippikon.security.AuthorizationContext;
import com.hippikon.security.IllegalAuthorizationException;
import com.hippikon.security.MutablePermissionSet;
import com.hippikon.security.PermissionSet;
import com.hippikon.security.Policy;
import com.hippikon.security.PolicyStore;
 
 /**
  * A default implementation of a ProjectPolicy that encapsulates the
  * logic required to determine the user permissions based on their
  * association with an <b>instance</b> of a Project rather than the class
  * of Project.
  *
  * This uses the project team, assigned user and owner checks to determine
  * user permissions
  *
  * @author Dale Churchett
  * @version $Id: ProjectPolicy.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 public class ProjectPolicy extends Policy {
  
     private Project project;
 
     /**
      * Creates a new ProjectPolicy instance
      */
     public ProjectPolicy(Object res, AuthorizationContext ctx) 
     throws IllegalAuthorizationException {
 
         super(res, ctx);
         this.project = (Project)res;
     }
 
     /**
      * Determines if the user making the access attempt
      * is 'the-teamleader', 'the-sales-executive' or 
      * a 'group-member'. These entries are listed in 
      * the {@link PolicyStore} for a Project ProtectedResource
      */
     protected List<String> determineUserPrincipals() {
 
         List<String> list = new ArrayList<String>();
 
         if (ctx.getUserGUID().equals(project.getTeamLeaderGUID())) {
             list.add("the-teamleader");
         }
         if (ctx.getUserGUID().equals(project.getOwnerGUID())) {
             list.add("the-sales-executive");
         }
         if (isInProjectTeam()) {
             list.add("group-member");
         }
         return list;
     
     }
 
     // determines if the user making the access attempt
     // is a member of the Project Team
     //
     private boolean isInProjectTeam() {
         List<String> list = project.getProjectTeamGUIDs();
         return (list.contains(ctx.getUserGUID())) ? true : false;
     }
 
     /**
      * Turns off write and control if the Project is in the CLOSED state
      */
     protected PermissionSet doFinal(PermissionSet perms) {
 
         if (getResourcePathInContext().contains("ProductChange")) {
             return perms;
         }
 
         MutablePermissionSet mps = createMutablePermissionSet(perms);
 
         if (project.isClosed()) {
             mps.setReadOnly();
         }
         return mps;
     }
 
 }

