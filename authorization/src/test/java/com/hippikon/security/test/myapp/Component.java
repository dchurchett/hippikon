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
 
 /**
  * Simple stub to use for unit testing
  *
  * @author Dale Churchett
  * @version $Id: Component.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 @ProtectedResource(name="Component")
 public class Component extends BusinessObjectImpl {

	private static final long serialVersionUID = 5203027899779284622L;
 
 
 }

