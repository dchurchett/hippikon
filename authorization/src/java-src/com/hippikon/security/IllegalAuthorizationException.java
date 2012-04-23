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
  * Signals whether any access to a ProtectedResource
  * is denied on the grounds that basic authorization data provided
  * in the {@link AuthorizationContext} is either not present
  * or invalid.<p>
  *
  * The exception may also be thrown by {@link Policy} implementations should
  * a request be made that does not fulfill the minimal pre-conditions
  * required for access to be granted.<p>
  *
  * The IllegalAuthorizationException should not be used for application 
  * logic, but should result in a log entry being generated or a 
  * notification event being triggered. Any time this exception is 
  * thrown a possible breach of security may be underway that should 
  * be investigated promptly.<p>
  *
  * @author Dale Churchett
  * @version $Id: IllegalAuthorizationException.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 public class IllegalAuthorizationException extends Exception {
 
	private static final long serialVersionUID = -6287878926063430879L;

	/**
      * Creates a new IllegalAuthorizationException with descriptive
      * error message
      *
      * @param msg a descriptive error message
      */
     public IllegalAuthorizationException(String msg) {
         super(msg);
     }
 
 }

