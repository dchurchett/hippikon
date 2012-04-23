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
import org.apache.log4j.*;

 
 /**
  * A default implementation of an Policy for an PurchaseOrder
  *
  * @author Dale Churchett
  * @version $Id: PurchaseOrderPolicy.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  */
 public class PurchaseOrderPolicy extends DefaultObjectPolicy {
 
     private PurchaseOrder po;
     private Logger log = Logger.getLogger("com.hippikon.security.test.PurchaseOrderPolicy");
 
     /**
      * Creates a new PurchaseOrderPolicy object
      */
     public PurchaseOrderPolicy(Object res, AuthorizationContext ctx)
     throws IllegalAuthorizationException {
         super(res, ctx);
         this.po = (PurchaseOrder)res;
     }
 
     /**
      * Determines if the user specified in the AuthorizationContext 
      * is either 'the-teamleader' or 'the-sales-executive', 'the-vendor' or 
      * 'the-buyer'
      */
     protected List<String> determineUserPrincipals() {
 
         List<String> list = new ArrayList<String>();
 
         // this logic needs checking out!
         //
         if (po.isVendor()) {
             if (ctx.getUserGUID().equals(po.getPartnerGUID())) {
                 list.add("the-vendor");
                 log.debug("the-vendor principal deterimined");
             }
         } else {
             if (ctx.getUserGUID().equals(po.getAssignedUserGUID())) {
                 list.add("the-teamleader");
             }
             if (ctx.getUserGUID().equals(po.getOwnerGUID())) {
                 list.add("the-sales-executive");
             }
         }
 
         return list;
     }
 
     /**
      * Turns off write, control and delete if this isn't the latest version
      */
     protected PermissionSet doFinal(PermissionSet perms) {
 
         MutablePermissionSet mps = createMutablePermissionSet(perms); 
 
         if (!isLatestVersion()) {
             mps.setReadOnly();
         }
 
         return mps;
     }
  
 
     private boolean isLatestVersion() {
         return true;
     }
 
 }

