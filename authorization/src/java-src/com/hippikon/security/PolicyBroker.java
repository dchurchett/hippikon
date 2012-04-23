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
 
 import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;

import com.hippikon.io.FileUtil;
 
 /**
  * The PolicyBroker is responsible for returning an instance of a {@link Policy}
  * that is defined for a {@link ProtectedResource} being accessed in an 
  * {@link AuthorizationContext}.<p>
  *
  * The rules that bind ProtectedResources with specialized Policy implementations
  * must be entered in a file named '[productID]-resource.policies' that is 
  * located in the system classpath.<p>
  *
  * The entries in the file should be in the standard java Properties format
  * (i.e., key  = value), where the key should be [ProtectedResource.name()].policy.classname.<p>
  *
  * <b>Example:</b><p>
  * 
  * <pre>
  * # entry for the Job protected resource
  * Project.policy.classname = com.yourdomain.security.ProjectPolicy
  * </pre>
  *
  * If a {@link PermissionSet} is requested for ProtectedResource that has no
  * Policy implementation bound to it, the {@link DefaultObjectPolicy} class
  * is used.<p>
  *
  * @author Dale Churchett
  * @version $Id: PolicyBroker.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 class PolicyBroker {
 
     private static Map<String, Properties> propsCache;
     private static final String RESOURCE_POLICY_FILE = ".resource.policies";
     private static Logger log = Logger.getLogger("com.hippikon.security.PolicyBroker");
 
     // initialize the cache
     //
     static {
         propsCache = new HashMap<String, Properties>();
     }
 
     /**
      * Loads the ProtectedResource->Policy classname properties file
      * for the product being accessed
      */
     private static Properties loadProperties(AuthorizationContext ctx)
     throws IOException {
 
         Properties props = new Properties();
         synchronized(props) {
 
             FileInputStream in = null;
 
             try {
 
                 String propsFilename = getPropsFilename(ctx.getProductID());
                 File propsFile = FileUtil.findFileInClasspath(propsFilename);
                 in = new FileInputStream(propsFile);
                 props.load(in);
 
                 return props;
 
             } catch (IOException e) {
                 log.error("FATAL ERROR: PolicyBroker.loadProperties() could not find resource policy file to load", e);
                 throw e;
             } finally {
                 try {
                     if (in != null) in.close();
                 } catch (IOException e) { }
             }
         }
     }
 
 
     /**
      * Since the properties for each product will be accessed often, we
      * cache the properties object once loaded
     */
     private static Properties getProperties(AuthorizationContext ctx)
     throws IOException {
 
         synchronized(propsCache) {
 
             String productID = ctx.getProductID();
             Properties props = propsCache.get(productID);
             if (props != null) {
             } else {
                 props = loadProperties(ctx);
                 propsCache.put(productID, props);
             }
             return props;
         }
     }
 
 
     /**
      * Returns the correct filename for the specified productID
      * resource.policies file
      */
     private static String getPropsFilename(String productID) throws IOException {
 
         if (productID == null || productID.equals("")) 
             throw new IOException("NULL or blank productID passed to PolicyBroker");
 
         // pad the productID to be 3 chars long (e.g., 001, 002)
         //
         StringBuffer sb = new StringBuffer();
         for (int i = (3 - productID.length()); i > 0; i--) {
             sb.append("0");
         }
         sb.append(productID);
         return "hippikon.product-id." + sb.toString() + RESOURCE_POLICY_FILE;
          
     }
 
 
     /**
      * Returns the correct Policy for a ProtectedResource. This method uses the 
      * Java Reflection API and passes the {@link AuthorizationContext} through
      * to the Policy implementation. Each policy implementation must provide
      * a constructor that takes a ProtectecResource and an AuthorizationContext
      * as method parameters (in that order).
      *
      * @param res the ProtectedResource to find the Policy for
      * @param ctx the AuthorizationContext of the access
      *
      * @exception PolicyStoreLoadException thrown if the Policy could not be loaded
      * or instantiated
      */
	 @SuppressWarnings("unchecked")
	static Policy getPolicy(Object res, AuthorizationContext ctx) 
     throws PolicyStoreLoadException {
 
         try {
 
             Properties props = getProperties(ctx);
 
             String name = new ProtectedResourceWrapper(res).getResourceName();
             String policyName = props.getProperty(name + ".policy.classname");
         
             // if no policy is defined use a default that 
             // does not apply any user specific PermissionSet logic
             //
             // TODO: get this out of a property file so clients can specify their 
             // own default class, but provide this as the default for easy out-of-the-box
             // implementations
             //
             if (policyName == null) {
                 policyName = "com.hippikon.security.DefaultObjectPolicy";
             }
 
             Class policyClass = Class.forName(policyName);
             Class[] constructorParams = new Class[] { Object.class, AuthorizationContext.class };
             Constructor constructor = policyClass.getConstructor(constructorParams);
 
             Object[] objParams = new Object[] { res, ctx };
             Object policy = constructor.newInstance(objParams);
 
             return (Policy)policy;
 
         } catch (Exception e) {
             log.debug(e.getMessage(), e);
             throw new PolicyStoreLoadException(e.getMessage());
         }
     }
 
 }

