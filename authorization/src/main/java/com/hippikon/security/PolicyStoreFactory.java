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
 
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
 
 /**
  * The PolicyStoreFactory class is responsible for loading the 
  * correct {@link PolicyStore} class for a specified product and
  * user account.<p>
  *
  * The Factory design pattern (ref: Design Patterns: Elements of 
  * Reusable Object Oriented Software) has been applied to this class to 
  * abstract the loading and retrieval logic of PolicyStore
  * objects for each product and/or account and provide the ability
  * to implement a Singleton class that may provide a cache 
  * for efficiency without any effect on client code.<p>
  *
  * The class is used internally to the Hippikon framework implementation 
  * and not exposed to clients in the public API.
  * 
  * @author Dale Churchett
  * @version $Id: PolicyStoreFactory.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 abstract class PolicyStoreFactory {
 
     // stores loaded PolicyStore objects
     //
     private static Map<String, PolicyStore> storeCache;
 
     // a thread that sweeps the cache at regular intervals
     //
     private static Thread cacheSweeperThread;
 
     private static Logger log = Logger.getLogger("com.hippikon.security.PolicyStoreFactory");
 
 
     // initialize the cache and sweeper thread
     //
     static {
         storeCache = new HashMap<String, PolicyStore>();
         cacheSweeperThread = new Thread(new CacheSweeper());
         cacheSweeperThread.start();
     }
 
 
     /**
      * Returns the correct {@link PolicyStore} for the 
      * accountID and productID obtained from the AuthorizationContext.
      *
      * @param ctx the {@link AuthorizationContext} for the authorization request
      *
      * @exception PolicyStoreLoadException thrown if the PolicyStore for
      * the account could not be returned. This should be considered a fatal
      * application error and treated accordingly.
      */
     static PolicyStore getPolicyStore(AuthorizationContext ctx) 
     throws PolicyStoreLoadException {
 
         // we can retrieve the correct policy store using the productID
         // and accountID from the AuthorizationContext, but for now
         // we are using a simple policy store for the working prototype
         // a more robust implementation would take the productID and accountID
         // as constructor arguments and either load from a db schema or from
         // an XML file. The factory may also be responsible for keeping the
         // the PolicyStore object in a cache for efficiency
         //
         synchronized(storeCache) {
 
             String productID = ctx.getProductID();
 
             if (!(storeCache.containsKey(productID))) {
                 PolicyStore store = new XMLPolicyStore(productID);
                 storeCache.put(productID, store);
                 return store;
             } else {
                 return (PolicyStore)storeCache.get(productID);
             }
         }
     }
 
 
     /**
      * A callback method for the CacheSweeper to call at regular intervals
      * This should not be used by other classes.
      */
     static void flushCache() {
         log.debug("Flushing cache");
         synchronized(storeCache) {
             storeCache.clear();
         }
     }
 
 }

