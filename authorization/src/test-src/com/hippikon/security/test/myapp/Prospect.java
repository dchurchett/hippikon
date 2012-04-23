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

import com.hippikon.security.ProtectedResource;
 
 /**
  * A simple implementation of the Prospect domain object provided for
  * the unit tests of the authorization API
  * 
  * @author Dale Churchett
  * @version $Id: Prospect.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 @ProtectedResource(name="Prospect")
 public class Prospect extends BusinessObjectImpl {
 

	private static final long serialVersionUID = -6750898727497935303L;
	private PurchaseOrder po;
 
     public Prospect() {
         super();
         this.po = new PurchaseOrder();
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
         return "NewCo Springs Ltd.,";
     }
 
     public String getAssignedUserGUID() {
         return "";
     }
 
     public String getOwnerGUID() {
         return po.getOwnerGUID();
     }
 
     public PurchaseOrder getPO() {
         return po;
     }
 
 }

