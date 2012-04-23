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
import java.util.Date;
import java.util.List;

import com.hippikon.security.ProtectedResource;
 
 /**
  * A simple implementation of the Project domain object provided for
  * the working prototype of the authorization API.
  *
  * Note the addition of the getProjectTeamGUIDs() method.
  *
  * There is also a ProjectPolicy class that handles the specifics
  * of the Project business logic.
  */
@ProtectedResource(name="Project")
public class Project extends BusinessObjectImpl {
 
	private static final long serialVersionUID = 1606097767638802484L;
	
	private PurchaseOrder po;
    private boolean isClosed;
 
     public Project() {
         super();
         this.po = new PurchaseOrder();
         this.isClosed = false;
     } 
 
     public String getAccountID() {
         return "SAL0001";
     }
 
     public String getGUID() {
         return "12341234ABCDASDE";
     }
 
     public Date getCreateDate() {
         return new Date();
     }
 
     public String getCreatorGUID() {
         return "xxxx2332xxxx";
     }
 
     public String getName() {
         return "NewCo Widgets";
     }
 
     public String getTeamLeaderGUID() {
         return po.getAssignedUserGUID();
     }
 
     public String getOwnerGUID() {
         return po.getOwnerGUID();
     }
 
     public PurchaseOrder getPO() {
         return po;
     }
 
     public List<String> getProjectTeamGUIDs() {
         ArrayList<String> list = new ArrayList<String>();
         list.add(getOwnerGUID());
         list.add(getTeamLeaderGUID());
         list.addAll(getParticipantsInTaskList());
         return list;
     }
 
     public boolean isClosed() {
         return isClosed;
     }
 
     private List<String> getParticipantsInTaskList() {
 
         // lookup the workflow activities
         //
         return new ArrayList<String>();
     }
 
     public void setClosed() {
         isClosed = true;
     }
 
     public void setPO(PurchaseOrder po) {
         this.po = po;
     }
 
     public void setOpen() {
         this.isClosed = false;
     }
     
 }

