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
 
 import com.hippikon.security.AuthorizationContext;
import com.hippikon.security.DefaultObjectPolicy;
import com.hippikon.security.IllegalAuthorizationException;
import com.hippikon.security.MutablePermissionSet;
import com.hippikon.security.PermissionSet;

 
 /**
  * A default implementation of a QuotePolicy that encapsulates the
  * logic required to determine the user permissions based on their
  * association with an <b>instance</b> of a Quote instance.
  *
  * @author Dale Churchett
  * @version $Id: InvoicePolicy.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 public class InvoicePolicy extends DefaultObjectPolicy {
 
     private Invoice invoice;
 
     /**
      * Creates a new QuotePolicy instance
      */
     public InvoicePolicy(Object res, AuthorizationContext ctx) 
     throws IllegalAuthorizationException {
 
         super(res, ctx);
         this.invoice = (Invoice)res;
     }
 
     /**
      * Turns off write and control if the Quote has been versioned
      */
     protected PermissionSet doFinal(PermissionSet perms) {
 
         MutablePermissionSet mps = createMutablePermissionSet(perms); 
 
         if (invoice.getVersionNumber() >= 1) {
             mps.setReadOnly();
         }
         return mps;
     }
 }

