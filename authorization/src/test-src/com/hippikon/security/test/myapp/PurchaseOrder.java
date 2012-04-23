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

import com.hippikon.security.ProtectedResource;
 
 @ProtectedResource(name="PurchaseOrder")
 public class PurchaseOrder extends Modification {
 
	private static final long serialVersionUID = -8537767116646076945L;
	private boolean isSub;
 
     public PurchaseOrder() {
         isSub = false;
     }
 
 
     public String getAssignedUserGUID() {
         return "12341234";
     }
 
     public String getOwnerGUID() {
         return "xxxxxx";
     }
 
     public boolean isVendor() {
         return isSub;
     }
 
     public String getPartnerGUID() {
         return "test-partner-guid";
     }
 
     public boolean noBidFlag() {
         return false;
     }
 
     public long getVersionNumber() {
         return 0;
     }
 
     public void setVendor() {
         this.isSub = true;
     }
 }

