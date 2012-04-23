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
 
 import org.apache.log4j.*;
import java.util.*;
 
 /**
  * The PermissionsFactory class provides a convenient and simple mechanism for obtaining
  * a {@link PermissionSet} for a {@link ProtectedResource} made by a user within an 
  * {@link AuthorizationContext}.<p>
  * 
  * Once a user has been authenticated, a user may need access to different
  * resources within an application. Each application may provide its own
  * authorization policy implementations to serve its specific needs. The 
  * authorization API can therefore said to be a framework, where the hooks
  * for extensibility and specialization are in the form of {@link Policy}
  * implementations.<p>
  *
  * To obtain a PermissionSet for a ProtectedResource:<p>
  *
  * <pre>
  * try {
  *     AuthorizationContext ctx = // a context object should be available
  *     ProtectedResource res = // a business object
  *
  *     PermissionSet resPerms = PermissionsFactory.getPermissions(res, ctx);
  *
  *     if (resPerms.canRead()) {
  *         // do something
  *     }
  * } catch (IllegalAuthorizationException e) {
  *     // log and direct to error page
  * } catch (ResourceNotFoundException re) {
  *     // this is an application error
  * }
  * </pre>
  *
  * @author Dale Churchett
  * @version $Id: PermissionsFactory.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 public abstract class PermissionsFactory {
 
     // for debugging
     //
     private static Logger log = Logger.getLogger("com.hippikon.security.PermissionsFactory");
 
     /**
      * No instances of this class may be created. Clients must use
      * the static methods only.
      */
     private PermissionsFactory() { }
 
     /**
      * Returns the complete PermissionSet for a ProtectedResource being
      * accessed within a AuthorizationContext.<p>
     * @param <T>
      *
      * @param res the ProtectedResource being accessed
      * @param ctx the AuthorizationContext containing data about an authenticated user
      *
      * @exception IllegalAuthorizationException thrown if the AuthorizationContext contains invalid
      * data or the use accessing the ProtectedResource can not be authorized. This is semantically
      * different than if the user is not allowed to access the resource; in this case no flags
      * will be set on the PermissionSet object returned.
      * @exception ResourceNotFoundException thrown if no entry in the {@link PolicyStore}
      * can be located in order to determine the PermissionSet object to return
      *
      * @pre res != null
      * @pre ctx != null
      */
     public static <T> PermissionSet getPermissions(Object res, AuthorizationContext ctx) 
     throws IllegalAuthorizationException, ResourceNotFoundException {
 
         // ensure the pre-conditions are met
         //
         if (res == null || ctx == null)
             throw new IllegalAuthorizationException("NULL objects passed to PermissionsFactory");
 
         try {
 
             List<Object> resources = new ArrayList<Object>();
             resources.add(res);
             return getPermissions(resources, ctx);
 
         } catch (ResourceNotFoundException e) {
             throw e;
         } catch (Exception e) {
             log.debug(e.getMessage(), e);
             throw new IllegalAuthorizationException(e.getMessage());
         }
     }
 
 
     /**
      * Returns the complete PermissionsSet for a class of ProtectedResource being
      * accessed within a AuthorizationContext. This provided mainly to determine
      * if new instances of the class may be created. In this case, the 
      * {@link PermissionSet#canCreate()} flag will return true.<p>
     * @param <T>
      *
      * @param c a class that inherits the ProtectedResource class that is being
      * accessed
      * @param ctx the AuthorizationContext containing data about an authenticated user
      *
      * @exception IllegalAuthorizationException thrown if the AuthorizationContext contains invalid
      * data or the user accessing the ProtectedResource can not be authorized. This is semantically
      * different than if the user is not allowed to access the resource; in this case no flags
      * will be set on the PermissionSet object returned.
      * @exception ResourceNotFoundException thrown if no entry in the {@link PolicyStore}
      * can be located in order to determine the PermissionSet object to return
      * 
      * @pre ctx != null
      */
     public static <T> PermissionSet getPermissions(Class<T> c, AuthorizationContext ctx)
     throws IllegalAuthorizationException, ResourceNotFoundException {
 
         // we don't allow Configurable objects to be passed into this method 
         // since they must be objects, not classes
         //
         _checkForConfigurableInstance(c);
 
         // ensure the pre-condition is met
         //
         if (ctx == null)
             throw new IllegalAuthorizationException("NULL AuthorizationContext passed to PermissionsFactory");
 
         // only top-level objects may be checked with this method
         // since the object does not exist yet
         //
         try {
 
             LinkedList<String> resources = new LinkedList<String>();
 
             String resourceName = new ProtectedResourceWrapper(c).getResourceName();
 
             // set up the context to pass through to the policies
             //
             List<String> resPath = new ArrayList<String>();
             resPath.add(resourceName);
             ctx.setResourcePath(resPath);
 
             PolicyStore store = PolicyStoreFactory.getPolicyStore(ctx);
 
             resources.add(resourceName);
 
             // here the roles are the only principals a user has since there 
             // is no instance to determine user principals
             //
             PermissionSet perms = store.getPermissions(resources, ctx.getUserRoles());
 
             return perms;
 
         } catch (Exception e) {
             log.debug(e.getMessage(), e);
             throw new IllegalAuthorizationException(e.getMessage());
         }
 
     }
 
     // throws an exception if a class implements Configurable
     //
     private static <T> void _checkForConfigurableInstance(Class<T> c) throws IllegalAuthorizationException {
 
         if (c.getName().equals(Configurable.class.getName()))
             throw new IllegalAuthorizationException("Configurable class passed into PermissionsFactory");
 
         Class<?>[] classInterfaces = c.getInterfaces();
         for (int i = 0; i < classInterfaces.length; i++) {
             if (classInterfaces[i].getName().equals(Configurable.class.getName())) {
                 throw new IllegalAuthorizationException("Classes that implement Configurable may not be checked by class");
             }
         }
     }
 
 
     /**
      * A convenience method provided to remove the need to create a new List 
      * if there is only one parent ProtectedResource object that may 
      * contain child objects.<p>
     * @param <T>
      *
      * @param res the parent ProtectedResource that may have rules defined
      * for child ProtectedResource objects
      * @param c a class that inherits the ProtectedResource class that is being
      * accessed
      * @param ctx the AuthorizationContext containing data about an authenticated user
      *
      * @exception IllegalAuthorizationException thrown if the AuthorizationContext contains invalid
      * data or the user accessing the ProtectedResource can not be authorized. This is semantically
      * different than if the user is not allowed to access the resource; in this case no flags
      * will be set on the PermissionSet object returned.
      * @exception ResourceNotFoundException thrown if no entry in the {@link PolicyStore}
      * can be located in order to determine the PermissionSet object to return
      * 
      * @pre res != null
      * @pre ctx != null
      */
     public static <T> PermissionSet getPermissions(Object res, Class<T> c, AuthorizationContext ctx)
     throws IllegalAuthorizationException, ResourceNotFoundException {
 
         // ensure the pre-conditions are met
         //
         _checkForConfigurableInstance(c);
         if (res == null || ctx == null)
             throw new IllegalAuthorizationException("NULL objects passed to PermissionsFactory");
 
         List<Object> resources = new ArrayList<Object>();
         resources.add(res);
         return getPermissions(resources, c, ctx);
     }
 
     
     /**
      * Returns the complete PermissionSet for a class of ProtectedResource being accessed 
      * in the context of a List of {@link ProtectedResource} objects. The PermissionSet 
      * returned will include the combination of all the ProtectedResources objects, along 
      * plus those defined for the Class. The class permissions will not include any
      * user ACLs since an instance is required in order to execute the 
      * {@link Policy#determineUserPrincipals()} method.<p>
     * @param <T>
      * 
      * @param resources a list of ProtectedResource objects that define the object hierachy
      * within which a Class is defined
      * @param c the Class being accessed within an AuthorizationContext. The class must
      * be a subtype of ProtectedResource
      *
      * @exception IllegalAuthorizationException thrown if the AuthorizationContext contains invalid
      * data or the user accessing the ProtectedResource can not be authorized
      * @exception ResourceNotFoundException thrown in no entry in the {@link PolicyStore}
      * can be located in order to determine the PermissionSet object to return
      *
      * @pre resources != null && resources.size() >= 1
      * @pre ctx != null
      */
     public static <T> PermissionSet getPermissions(List<Object> resources, Class<T> c, AuthorizationContext ctx)
     throws IllegalAuthorizationException, ResourceNotFoundException {
 
         // ensure pre-conditions are met
         //
         _checkForConfigurableInstance(c);
         if (resources == null || ctx == null)
             throw new IllegalAuthorizationException("NULL objects passed to PermissionsFactory");
         if (resources.size() < 1)
             throw new IllegalAuthorizationException("Empty resource list passed to PermissionsFactory");
         
         try {
 
             LinkedList<String> resourceList = new LinkedList<String>();
 
             PolicyMediator mediator = new PolicyMediator(resources, ctx);
             resourceList.addAll(mediator.getResourceList());
             ctx.setResourcePath(resourceList);
 
             // now set up for the class - note there are no user types for a Class
             // of ProtectedResource, so we just need to get the ResourceName and 
             // add to the list
             //
             String classResName = new ProtectedResourceWrapper(c).getResourceName();
             resourceList.add(classResName);
 
             // now we can get the permissions by passing in the user types and
             // resource names to the PolicyStore
             //
             PolicyStore store = PolicyStoreFactory.getPolicyStore(ctx);
 
             // now all the policy objects the chance to perform
             // a final permissions check
             //
             return store.getPermissions(resourceList, mediator);
             
 
         } catch (Exception e) {
             log.debug(e.getMessage(), e);
             throw new IllegalAuthorizationException(e.getMessage());
         }
     }
 
 
     /**
      * Returns the complete PermissionSet for a ProtectedResource
      * being accessed within an AuthorizationContext, where the 
      * PermissionSet is influenced by a hierarchy of ProtectedResources.<p>
      *
      * Some resources may need to inherit the permissions of parent
      * objects, or be affected by other resources in an application. In 
      * these cases, the complete set of ProtectedResources should be
      * passed into this method as an array populated in the order of 
      * the hierarchy. The last entry in the list is the actual ProtectedResource
      * being accessed by a user.<p>
      *
      * The hierarchy of resource names must match an ACL structure defined 
      * in a {@link PolicyStore}. If a hierarchy is not defined in the 
      * PolicyStore, each PermissionSet will be retrieved and combined 
      * to compute the final PermissionSet.<p>
      * 
      * @param resources an array of ProtectedResource objects listed in
      * order of importance. This may mirror a hierarchy of objects
      * that influence lower order entries. In the event a matching
      * hierarchy entry can not be located in the appropriate {@link PolicyStore}
      * the authorization framework will attempt to retrieve the top-level
      * PermissionSet objects for each ProtectedResource in the array and
      * combine them using an OR logical operation.
      *
      * @return the complete PermissionSet of a ProtectedResource being accessed
      * with an AuthorizationContext and influenced by othe ProtectedResources
      * in an application
      *
      * @pre resources != null && resource.size() >= 1
      * @pre ctx != null
      */
     public static PermissionSet getPermissions(List<Object> resources, AuthorizationContext ctx) 
     throws IllegalAuthorizationException, ResourceNotFoundException {
 
         // ensure pre-conditions are met
         //
         if (resources == null || ctx == null)
             throw new IllegalAuthorizationException("NULL objects passed to PermissionsFactory");
         if (resources.size() < 1)
             throw new IllegalAuthorizationException("Empty resource list passed to PermissionsFactory");
 
         try {
 
             LinkedList<String> resourceList = new LinkedList<String>();
 
             PolicyMediator mediator = new PolicyMediator(resources, ctx);
             resourceList.addAll(mediator.getResourceList());
             ctx.setResourcePath(resourceList);
 
             // now we can get the permissions by passing in the user types and
             // resource names to the PolicyStore
             //
             PolicyStore store = PolicyStoreFactory.getPolicyStore(ctx);
             return store.getPermissions(resourceList, mediator);
 
         } catch (Exception e) {
             log.debug(e.getMessage(), e);
             throw new IllegalAuthorizationException(e.getMessage());
         }
     }
 
 
 }

