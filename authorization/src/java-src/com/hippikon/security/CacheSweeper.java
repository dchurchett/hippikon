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
 
 import org.apache.log4j.Logger;
 
 /**
  * Provides a simple Timer that flushes the policy store cache stored
  * in the PolicyStoreFactory class at regular intervals that may be
  * defined at deploy time by setting the following system environment
  * property:<p>
  *
  * <pre>
  * policy-store-factory.cache-flush.interval
  * </pre><p>
  *
  * This value must be in milliseconds. If not present, a default of 
  * 6 hours is used.<p>
  *
  * @author Dale Churchett
  * @version $Id: CacheSweeper.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 class CacheSweeper implements Runnable {
 
     private long sleepInterval;
     private static Logger log = Logger.getLogger("com.hippikon.security.CacheSweeper");
 
     /**
      * Creates a new CacheSweeper Runnable objects. Care must be taken
      * to only create one of these in the PolicyStoreFactory
      */
     CacheSweeper() {
 
         String intStr = System.getProperty("policy-store-factory.cache-flush.interval");
         if (intStr != null)
             this.sleepInterval = Long.parseLong(intStr);
         else
             // default to six hours
             //
             this.sleepInterval = 21600000;
     }
 
 
     /**
      * Sleeps for the specified number of milliseconds and flushes
      * the PolicyStoreFactory cache
      */
     public void run() {
         for(;;) {
             try {
                 Thread.sleep(sleepInterval);
                 log.debug("Flushing policy-store cache");
                 PolicyStoreFactory.flushCache();
             } catch (Exception e) {
                 log.warn(e.getMessage());
             }
         }
     }
 
 }

