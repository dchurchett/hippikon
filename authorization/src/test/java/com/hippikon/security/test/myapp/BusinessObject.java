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
 
 import java.util.Date;
 
 //
 // this is already documented on zoot
 //
 
 public interface BusinessObject {
 
     /**
      * The unique identifier of the account the business object belongs to
      * @return String. May not be null.
      */
     public String getAccountID();
     
     /**
      * The unique identifier for the object, assigned on creation and
      * subsequently used to retrieve. Once set this attribute becomes invariant.
      * @return a String identifier. May not be null.
      */
     public String getGUID();
     
     /**
      * The unique identifier of the user that created the object, often
      * used to determine principals of 'the-creator' at runtime or to filter
      * out object lists that 'belong' to a user.
      * @return a String user identifer
      */
     public String getCreatorGUID();
     
     /**
      * The date on which the object was created. Useful for traceability.
      * @return a Date object. May not be null.
      */
     public Date getCreateDate();
     
     /**
      * Returns the name identifier of the business object.
      * @return a String name
      */
     public String getName();
 
 }

