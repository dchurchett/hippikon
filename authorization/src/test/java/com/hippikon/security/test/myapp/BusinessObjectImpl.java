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
 
 import java.io.Serializable;
import java.util.Date;
 
 /**
  * Minimalist implementation of the BusinessObject interface
  *
  * @author <a href="mailto:dale@hippikon.com">Dale Churchett</a>
  * @version $Id: BusinessObjectImpl.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  */
 public class BusinessObjectImpl implements BusinessObject, Serializable {
 

	 private static final long serialVersionUID = -4471428527617549180L;
	 protected String accountID;
     protected String guid;
     protected String creatorGUID;
     protected Date   createDate;
     protected String name;
 
     /**
      * Default constructor.  Does nothing more than instantiate.
      */
     public BusinessObjectImpl(){
     }
 
     /**
      * Creates a new BusinessObjectImpl class
      *
      * @param accountID the identifier of the corporate account
      * that owns the object instance. This is primarily used
      * by by the security layer to ensure no cross-referencing
      * of objects between accounts is possible.
      * @param guid the unique identifier for the object instance.
      * The GUID returned may be used to lookup the object or used as a
      * reference by other objects.
      * @param creatorGUID the unique identifer for the user that created
      * the object instance whose unique identifier is returned
      * by the call to {@link #getGUID()}. This value may be used
      * to lookup the user from the user directory.
      * @param createDate the date this object was created.
      * @param name a descriptive name of the object instance. The name
      * value should not be used to uniquely identify the object
      * instance; clients should use {@link #getGUID()} for this
      * purpose.
      *
      */
     public BusinessObjectImpl(String accountID, String guid, String creatorGUID,
                               Date createDate, String name){
         this.accountID   = accountID;
         this.guid        = guid;
         this.creatorGUID = creatorGUID;
         this.createDate  = createDate;
         this.name        = name;
     }
 
     /**
      * Returns the identifier of the corporate account
      * that owns the object instance. This is primarily used
      * by by the security layer to ensure no cross-referencing
      * of objects between accounts is possible.
      *
      * @return the accountID of the corporate account that owns
      * the object. This is a required field and may not be NULL
      * or an empty {@link java.lang.String}
      *
      * @pre the object has been created and the accountID
      * exists in the authentication subsystem
      *
      * @post a valid accountID is returned that exists in the
      * authentication subsystem. This may be used to reference the
      * account information such as whether the account is enabled
      * or disabled.
      */
     public String getAccountID(){
         return accountID;
     }
 
 
     /**
      * Returns the unique identifier for the object instance.
      * The GUID returned may be used to lookup the object or used as a
      * reference by other objects.
      *
      * @return the global unique identifier for the object instance. This
      * is a required field and may not be NULL or an empty
      * {@link java.lang.String}
      *
      * @pre the object has been created in the system
      * @post the global unique identifier for the object instance
      * is returned. This may be used to lookup the object in its
      */
     public String getGUID(){
         return guid;
     }
 
 
     /**
      * Returns the unique identifer for the user that created
      * the object instance whose unique identifier is returned
      * by the call to {@link #getGUID()}. This value may be used
      * to lookup the user from the user directory.
      *
      * @return the global unique identifier for the user that
      * created the object instance. This is a required field
      * and may not be NULL or an empty string.
      *
      * @pre the user GUID exists in the system and is associated
      * with a valid account. The user account may or may not be
      * enabled.
      *
      * @post a user GUID is returned that may be used to lookup
      * the user from the user directory subsystem. Only users
      * that are members of the same corporate account may reference
      * this information.
      */
     public String getCreatorGUID(){
         return creatorGUID;
     }
 
 
     /**
      * Returns the date the object instance was created.
      *
      * @return a {@link java.util.Date} object representing
      * the time the object was created. This is a required
      * field that may not be NULL.
      *
      * @pre the object instance has been created and assigned
      * a global unique identifier
      *
      * @post a valid {@link java.util.Date} object is returned
      * to the client.
      */
     public Date getCreateDate(){
         return createDate;
     }
     /**
      * Returns a descriptive name of the object instance. The name
      * value should not be used to uniquely identify the object
      * instance; clients should use {@link #getGUID()} for this
      * purpose.
      *
      * @return a descriptive name of the object instance. This
      * is a required field and may not be NULL or an empty string.
      *
      * @pre the object instance has been created and assigned
      * a global unique identifier
      *
      * @post getName() != null && getName().length <= 1
      */
     public String getName(){
         return name;
     }
 
     /**
      * Sets the identifier of the corporate account
      * that owns this object instance. This is primarily used
      * by by the security layer to ensure no cross-referencing
      * of objects between accounts is possible.
      */
     public void setAccountID (String accountID){
         this.accountID = accountID;
     }
     /**
      * Sets the unique identifier for the object instance.
      * The GUID returned may be used to lookup the object or used as a
      * reference by other objects.
      */
     public void setGUID(String guid){
         this.guid = guid;
     }
     /**
      * Sets the unique identifer for the user that created
      * the object instance whose unique identifier is returned
      * by the call to {@link #getGUID()}. This value may be used
      * to lookup the user from the user directory.
      */
     public void setCreatorGUID(String creatorGUID){
         this.creatorGUID = guid;
     }
     /**
      * Sets the date this object was created.
      */
     public void setCreateDate(Date createDate){
         this.createDate = createDate;
     }
     /**
      * Sets the descriptive name of this object instance. The name
      * value should not be used to uniquely identify the object
      * instance; clients should use {@link #getGUID()} for this
      * purpose.
      */
     public void setName(String name){
         this.name = name;
     }
 
 } // end
 
 

