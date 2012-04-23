/**
 * This software may be distributed under the terms
 * of the LGPL.
 * See www.gnu.org for details
 * Copyright Dale Churchett 2005. All Rights Reserved
 */
package com.hippikon.security.test.myapp;
 
 import com.hippikon.security.*;
 
 /**
  * A default implementation of a TaskListItem used
  * <b>for testing only</b>.
  *
  * @author Dale Churchett
  * @version $Id: TaskListItem.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 @ProtectedResource(name="TaskListItem")
 public class TaskListItem {
 
     /**
      * Default constructor
      */
     public TaskListItem() { }
 

     /**
      * Returns the teamleader user guid associated
      * with the workflow item
      */
     public String getTeamLeaderGUID() {
         return "12341234";
     }
 }

