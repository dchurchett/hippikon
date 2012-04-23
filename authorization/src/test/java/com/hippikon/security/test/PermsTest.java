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
package com.hippikon.security.test;
 
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.log4j.Logger;

import com.hippikon.security.AuthorizationContext;
import com.hippikon.security.Configurable;
import com.hippikon.security.ConfigurableProtectedResource;
import com.hippikon.security.DefaultAuthorizationContext;
import com.hippikon.security.IllegalAuthorizationException;
import com.hippikon.security.PermissionSet;
import com.hippikon.security.PermissionsFactory;
import com.hippikon.security.ProtectedResource;
import com.hippikon.security.ProtectedResourceNamingException;
import com.hippikon.security.ProtectedResourceWrapper;
import com.hippikon.security.test.myapp.Attachment;
import com.hippikon.security.test.myapp.Component;
import com.hippikon.security.test.myapp.ExecutiveSummary;
import com.hippikon.security.test.myapp.Modification;
import com.hippikon.security.test.myapp.ProductChange;
import com.hippikon.security.test.myapp.Project;
import com.hippikon.security.test.myapp.Prospect;
import com.hippikon.security.test.myapp.PurchaseOrder;
import com.hippikon.security.test.myapp.Report;
import com.hippikon.security.test.myapp.TaskList;
import com.hippikon.security.test.myapp.TaskListItem;

 
 /**
  * A simple class to demonstrate and test the authorization API. This uses
  * a default authenticated user in the role of participant and manager
  * who is the assigned user (and group-member) of a Project instance.<p>
  *
  * Future tests should include different combinations of a user to 
  * ensure coverage.
  * 
  * @author Dale Churchett
  * @version $Id: PermsTest.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 @SuppressWarnings("unused")
 public class PermsTest extends TestCase {
 
     private static Logger log = Logger.getLogger("com.hippikon.security.test.PermsTest");
     private PurchaseOrder po;
     private ExecutiveSummary report;
 
     /**
      * Creates a new PermsTest object to run in the JUnit
      * framework.
      */
     public PermsTest(String s) {
         super(s);
         this.po = new PurchaseOrder();
         this.report = new ExecutiveSummary();
     }
 
 
     /**
      * Ensures an exception is thrown when a class that doesn't have an entry
      * in the PolicyStore is passed to PermissionsFactory.
      */
     public void testNonProtectedResourceClass() {
         try {
 
             AuthorizationContext ctx = getTeamLeaderContext();
             PermissionsFactory.getPermissions(List.class, ctx);
             fail("Did not throw exception when a non-ProtectedResource class was looked up");
         } catch (Exception e) {
         }
     }
 
     /**
      * Ensures an exception is thrown when a null object is passed to the PermissionsFactory
      */
     public void testNullProtectedResource() {
         try {
             AuthorizationContext ctx = getManagerContext();
             PurchaseOrder po = null;
             PermissionSet perms = PermissionsFactory.getPermissions(po, ctx);
             fail("Did not throw exception when NULL ProtectedResource object was passed to the PermissionsFactory");
         } catch (Exception e) {
         }
     }
 
     /**
      * Ensures an exception is thrown when a null AuthorizationContext object is passed to the PermissionsFactory
      */
     public void testNullAuthorizationContext() {
 
         try {
             AuthorizationContext ctx = null;
             PermissionSet perms;
             perms = PermissionsFactory.getPermissions(PurchaseOrder.class, ctx);
             perms = PermissionsFactory.getPermissions(new PurchaseOrder(), ctx);
 
             fail("Did not throw exception when NULL AuthorizationContext object was passed to the PermissionsFactory");
 
         } catch (Exception e) {
         }
     }
 
     /**
      * Tests the Configurable interface mechanism
      */
     public void testConfigurableObject() {
         AuthorizationContext ctx = null;
         PermissionSet perms;
         try {
             ctx = getManagerContext();
         } catch (Exception e) {
             fail(e.getMessage());
         }
         try {
             perms = PermissionsFactory.getPermissions(Configurable.class, ctx);
             fail("Did not throw exception when Configurable class was passed to the PermissionsFactory");
         } catch (Exception e) {
         }
         try {
             perms = PermissionsFactory.getPermissions(Report.class, ctx);
             fail("Did not throw exception when Configurable class was passed to the PermissionsFactory");
         } catch (Exception e) {
         }
 
         try {
             perms = PermissionsFactory.getPermissions(new Report("FakeReport"), ctx);
             fail("Did not throw exception when fake report was object was passed to the PermissionsFactory");
         } catch (Exception e) {
         }
 
         try {
             perms = PermissionsFactory.getPermissions(new Report("SalesPipelineReport"), ctx);
             assertTrue(perms.canRead());
         } catch (Exception e) {
         }
     }
 
     /**
      * Ensures an exception is thrown when an empty list is passed to the PermissionsFactory
      */
     public void testEmptyList() {
         try {
             AuthorizationContext ctx = getManagerContext();
             List<ProtectedResource> list = new ArrayList<ProtectedResource>();
             PermissionsFactory.getPermissions(list, ctx);
 
             fail("Did not throw exception when an empty list was passed to the PermissionsFactory");
 
         } catch (Exception e) {
         }
 
         // just double check a list of size() == 1 still passes ok
         //
         try {
             AuthorizationContext ctx = getManagerContext();
             List<Object> list = new ArrayList<Object>();
             list.add(new PurchaseOrder());
             PermissionsFactory.getPermissions(list, ctx);
             
         } catch (Exception e) {
             fail(e.getMessage());
         }
     }
 
 
     /**
      * Tests a Project instance for the user
      */
     public void testProjectInstance() {
 
         try {
 
             AuthorizationContext ctx = getTeamLeaderContext();
             Project project = new Project();
 
             PermissionSet perms = PermissionsFactory.getPermissions(project, ctx);
 
             assertFalse(perms.canCreate());
             assertTrue(perms.canRead());
             assertTrue(perms.canWrite());
             assertTrue(perms.canControl());
             assertFalse(perms.canDelete());
 
             log.debug("Permissions for a Project Instance = " + getPermsAsString(perms));
 
         } catch (Exception e) {
             fail(e.getMessage());
         }
     }
 
     /**
      * Tests the permissions for a TaskListItem within a TaskList
      */
     public void testTaskListItem() {
 
         try {
 
             AuthorizationContext ctx = getTeamLeaderContext();
 
             Project project = new Project();
             TaskList taskList = new TaskList();
             TaskListItem taskListItem = new TaskListItem();
 
             List<Object> resources = new ArrayList<Object>();
             resources.add(project);
             resources.add(taskList);
             resources.add(taskListItem);
 
             PermissionSet perms = PermissionsFactory.getPermissions(resources, ctx);
             log.debug("Permissions for Project, TaskList, TaskListItem = " + getPermsAsString(perms));
 
             assertFalse(perms.canCreate());
             assertTrue(perms.canRead());
             assertTrue(perms.canWrite());
             assertTrue(perms.canControl());
             assertFalse(perms.canDelete());
             
         } catch (Exception e) {
             fail(e.getMessage());
         }
     }
 
     /**
      * Tests that the ProjectPolicy does not invoke setReadOnly()
      * on the permissions returned from the policy store
      * when the project is closed. Here we are testing object state and
      * the policy callback mechanism.
      */
     public void testClosedProjetInstanceProductChangeClass() {
 
         try {
 
             AuthorizationContext ctx = getTeamLeaderContext();
             Project project = new Project();
             project.setClosed();
 
             PermissionSet perms = PermissionsFactory.getPermissions(project, ProductChange.class, ctx);
             log.debug("Permissions for a Project Instance, ProductChange class = " + getPermsAsString(perms));
 
             assertTrue(perms.canCreate());
             assertTrue(perms.canRead());
             assertTrue(perms.canWrite());
             assertTrue(perms.canControl());
             assertFalse(perms.canDelete());
 
         } catch (Exception e) {
             fail(e.getMessage());
         }
     }
 
 
     /**
      * Tests a PRoject instance for the user that has been closed, which
      * is another test of state change based on policy callbacks.
      */
     public void testClosedProjectInstance() {
 
         try {
 
             AuthorizationContext ctx = getTeamLeaderContext();
             Project project = new Project();
             project.setClosed();
 
             PermissionSet perms = PermissionsFactory.getPermissions(project, ctx);
 
             assertFalse(perms.canCreate());
             assertTrue(perms.canRead());
             assertFalse(perms.canWrite());
             assertFalse(perms.canControl());
             assertFalse(perms.canDelete());
 
             log.debug("Permissions for a closed Project Instance = " + getPermsAsString(perms));
 
         } catch (Exception e) {
             fail(e.getMessage());
         }
     }
 
 
     /**
      * Tests a Project class create flags for the user
      */
     public void testProjectClass() {
         try {
             AuthorizationContext ctx = getTeamLeaderContext();
             PermissionSet perms = PermissionsFactory.getPermissions(Project.class, ctx);
 
             assertFalse(perms.canCreate());
             assertTrue(perms.canRead());
             assertFalse(perms.canWrite());
             assertFalse(perms.canControl());
             assertFalse(perms.canDelete());
 
             log.debug("Permissions for a Project Class = " + getPermsAsString(perms));
 
         } catch (Exception e) {
             fail(e.getMessage());
         }
     }
 
 
     /**
      * Tests a PurchaseOrder instance flags for the user
      */
     public void testPurchaseOrderInstance() {
         try {
             AuthorizationContext ctx = getTeamLeaderContext();
 
             PurchaseOrder po = new PurchaseOrder();
             PermissionSet poPerms = PermissionsFactory.getPermissions(po, ctx);
 
             assertTrue(poPerms.canCreate());
             assertTrue(poPerms.canRead());
             assertTrue(poPerms.canWrite());
             assertTrue(poPerms.canControl());
             assertFalse(poPerms.canDelete());
 
             log.debug("Permissions for a PurchaseOrder Instance = " + getPermsAsString(poPerms));
             
         } catch (Exception e) {
             fail(e.getMessage());
         }
     }
 
 
     /**
      * Tests the permissions for an ProductChange class within
      * a Project
      */
     public void testProjectInstanceECClass() {
 
         try {
 
             AuthorizationContext ctx = getTeamLeaderContext();
 
             Project project = new Project();
             ProductChange ec = new ProductChange();
             List<Object> list = new ArrayList<Object>();
             list.add(project);
 
             PermissionSet perms = PermissionsFactory.getPermissions(list, ProductChange.class, ctx);
 
             assertTrue(perms.canCreate());
             assertTrue(perms.canRead());
             assertTrue(perms.canWrite());
             assertTrue(perms.canControl());
             assertFalse(perms.canDelete());
             
             log.debug("Permissions for a Project instance, ProductChange class = " + getPermsAsString(perms));
 
         } catch (Exception e) {
             fail(e.getMessage());
         }
     }
 
 
     /**
      * Tests the permissions for a ExecutiveSummary
      */
     public void testExecutiveSummaryInstance() {
         try {
 
             AuthorizationContext ctx = getTeamLeaderContext();
             PermissionSet reportPerms = PermissionsFactory.getPermissions(report, ctx);
 
             assertFalse(reportPerms.canCreate());
             assertTrue(reportPerms.canRead());
             assertFalse(reportPerms.canWrite());
             assertFalse(reportPerms.canControl());
             assertFalse(reportPerms.canDelete());
 
             log.debug("Permissions for a Report Instance = " + getPermsAsString(reportPerms));
 
         } catch (Exception e) {
             e.printStackTrace();
             fail(e.getMessage());
         }
     }
 
     /**
      * Tests the ExecutiveSummary for a manager. This is a core report and therefore treated
      * the same way as any other object.
      */
     public void testManagerExecutiveSummaryAccess() {
         try {
 
             AuthorizationContext ctx = getManagerContext();
             PermissionSet reportPerms = PermissionsFactory.getPermissions(report, ctx);
 
             assertFalse(reportPerms.canCreate());
             assertTrue(reportPerms.canRead());
             assertFalse(reportPerms.canWrite());
             assertFalse(reportPerms.canControl());
             assertFalse(reportPerms.canDelete());
 
             log.debug("Permissions for a Report Instance = " + getPermsAsString(reportPerms));
 
         } catch (Exception e) {
             fail(e.getMessage());
         }
 
     }
 
     /**
      * Tests the permissions for a PurchaseOrder class within a Project instance
      */
     public void testProjectInstancePurchaseOrderClass() {
 
         try {
 
             AuthorizationContext ctx = getTeamLeaderContext();
             Project project = new Project();
 
             List<Object> list = new ArrayList<Object>();
             list.add(project);
 
             PermissionSet perms = PermissionsFactory.getPermissions(list, PurchaseOrder.class, ctx);
 
             assertFalse(perms.canCreate());
             assertTrue(perms.canRead());
             assertTrue(perms.canWrite());
             assertTrue(perms.canControl());
             assertFalse(perms.canDelete());
 
             log.debug("Permissions for a Project instance, PurchaseOrder class = " + getPermsAsString(perms));
 
         } catch (Exception e) {
             fail(e.getMessage());
         }
     }
 
     /**
      * Tests the permissions for a PurchaseOrder instance within a Project
      */
     public void testProjectInstancePurchaseOrderInstance() {
 
         try {
 
             AuthorizationContext ctx = getTeamLeaderContext();
             Project project = new Project();
 
             List<Object> list = new ArrayList<Object>();
             list.add(project);
             list.add(new PurchaseOrder());
 
             PermissionSet perms = PermissionsFactory.getPermissions(list, ctx);
 
             assertFalse(perms.canCreate());
             assertTrue(perms.canRead());
             assertTrue(perms.canWrite());
             assertTrue(perms.canControl());
             assertFalse(perms.canDelete());
 
             log.debug("Permissions for a Project instance, PurchaseOrder instance = " + getPermsAsString(perms));
 
         } catch (Exception e) {
             fail(e.getMessage());
         }
     }
 
     /**
      * Tests the permissions for adding an Attachment to an PurchaseOrder instance
      * within a Project
      */
     public void testProjectInstancePurchaseOrderInstanceAttachmentClass() {
 
         try {
 
             AuthorizationContext ctx = getTeamLeaderContext();
             Project project = new Project();
 
             List<Object> list = new ArrayList<Object>();
             list.add(project);
             list.add(new PurchaseOrder());
 
             PermissionSet perms = PermissionsFactory.getPermissions(list, Attachment.class, ctx);
 
             assertTrue(perms.canCreate());
             assertTrue(perms.canRead());
             assertTrue(perms.canWrite());
             assertTrue(perms.canControl());
             assertTrue(perms.canDelete());
 
             log.debug("Permissions for a Project instance, PurchaseOrder instance, Attachment class = " + getPermsAsString(perms));
 
         } catch (Exception e) {
             fail(e.getMessage());
         }
     }
 
     /**
      * Tests whether a manager has the right permissions when accessing
      * an Prospect instance
      */
     public void testManagerAccessToProspect() {
         try {
 
             AuthorizationContext ctx = getManagerContext();
             Prospect p = new Prospect();
 
             List<Object> list = new ArrayList<Object>();
             list.add(p);
 
             PermissionSet perms = PermissionsFactory.getPermissions(list, ctx);
 
             assertFalse(perms.canCreate());
             assertTrue(perms.canRead());
             assertTrue(perms.canWrite());
             assertFalse(perms.canControl());
             assertFalse(perms.canDelete());
 
             log.debug("Permissions for a Prospect instance for Manager = " + getPermsAsString(perms));
 
         } catch (Exception e) {
             fail(e.getMessage());
         }
     }
 
     /**
      * Tests to ensure a user that is not subscribed to a product cannot
      * access resources it contains
      */
     public void testProductAccess() {
     
         try {
             AuthorizationContext ctx = getIllegalSubscriptionContext();
             PermissionSet perms = PermissionsFactory.getPermissions(new PurchaseOrder(), ctx);
 
             assertFalse(perms.canCreate());
             assertFalse(perms.canRead());
             assertFalse(perms.canWrite());
             assertFalse(perms.canControl());
             assertFalse(perms.canDelete());
             
             log.debug("Permissions for a user with no subscriptions = " + getPermsAsString(perms));
             fail("An AuthorizationContext was created for a user with no subscriptions");
             
         } catch (Exception e) { }
     
     }
     
     /**
      * Tests the configurable protected resource mechanism
      */
     public void testConfigurableProtectedResource() {
    	 
    	 try {
	         AuthorizationContext ctx = getIllegalSubscriptionContext();
	         PermissionSet perms = PermissionsFactory.getPermissions(new ConfigurableProtectedResource("PurchaseOrder"), ctx);
	         
	         assertFalse(perms.canCreate());
	         assertFalse(perms.canRead());
	         assertFalse(perms.canWrite());
	         assertFalse(perms.canControl());
	         assertFalse(perms.canDelete());
	         
	         log.debug("Permissions for a user with no subscriptions = " + getPermsAsString(perms));
	         fail("An AuthorizationContext was created for a user with no subscriptions");
	         
	     } catch (Exception e) { }
    	 
     }
 
     /**
      * Tests the permissions for a vendor accessing a Component and an 
      * PurchaseOrder created by the supplier. They should not have any permissions on 
      * a component but would have read/control on the PurchaseOrder if it was sent to them
      * buy the supplier
      */
     public void testVendorAccess() {
 
         try {
 
             AuthorizationContext ctx = getVendorContext();
 
             Project project = new Project();
             project.setOpen();
             Component part = new Component();
             PurchaseOrder po = new PurchaseOrder();
             po.setVendor();
             project.setPO(po);
 
             List<Object> list = new ArrayList<Object>();
             list.add(project);
             list.add(part);
 
             PermissionSet perms = PermissionsFactory.getPermissions(list, ctx);
             log.debug("Permissions for a vendor viewing a part = " + getPermsAsString(perms));
 
             // the vendor should not be able to do anything with the part
             //
             assertFalse(perms.canCreate());
             assertFalse(perms.canRead());
             assertFalse(perms.canWrite());
             assertFalse(perms.canControl());
             assertFalse(perms.canDelete());
             
             list.clear();
             list.add(project);
             list.add(part);
             list.add(po);
 
             perms = PermissionsFactory.getPermissions(list, ctx);
             log.debug("Permissions for a vendor viewing a Project, Component, PurchaseOrder = " + getPermsAsString(perms));
 
             // but they can read and control the PurchaseOrder if it is sent to them
             //
             assertFalse(perms.canCreate());
             assertTrue(perms.canRead());
             assertFalse(perms.canWrite());
             assertTrue(perms.canControl());
             assertFalse(perms.canDelete());
             
         } catch (Exception e) {
             fail(e.getMessage());
         }
     }
 
     /**
      * Tests that a list containing one ProtectedResource can be passed
      * to the PermissionsFactory. This method was required due to a 
      * refactoring of that method implementation.
      */
     public void testBadResourceList() {
         try {
             AuthorizationContext ctx = getManagerContext();
             PurchaseOrder po = new PurchaseOrder();
             List<Object> list = new ArrayList<Object>();
             list.add(po);
             PermissionsFactory.getPermissions(list, ctx);
         } catch (Exception e) {
             fail(e.getMessage());
         }
     }
 
 
     /**
      * Ensures a user must be assigned at least one role
      */
     public void testNoRoleAssignment() {
         try {
			getNoRoleContext();
            fail("No exception thrown for a user with no roles assigned");
         } catch (Exception e) { }
     }
 
 
     /**
      * Ensures a user must belong to a corporate account that has 
      * subscriptions
      */
     public void testNoSubscriptions() {
         try {
             AuthorizationContext ctx = getNoSubscriptionsContext();
             fail("No exception thrown for a user with no subscriptions");
         } catch (Exception e) { }
     }
 
 
     /**
      * Ensures the ProtectedResourceWrapper correnct retrieves the resource name    
      * when invoked under different conditions. This test also checks where objects
      * are cast to supertypes
      */
	public void testProtectedResourceCast() {
 
         try {
 
             // demonstrates how an PurchaseOrder and ProduceChange can be cast to a Modification
             // depending on the context they are being accessed in
             //
             PurchaseOrder po = new PurchaseOrder();
             ProductChange pc = new ProductChange();
 
             assertEquals(TestProtectedResourceWrapper.getResourceName(PurchaseOrder.class, pc), "PurchaseOrder");
             assertEquals(TestProtectedResourceWrapper.getResourceName(Modification.class, pc), "Request");
             assertEquals(TestProtectedResourceWrapper.getResourceName(PurchaseOrder.class, po), "PurchaseOrder");
             assertEquals(TestProtectedResourceWrapper.getResourceName(Modification.class, po), "Request");
 
         } catch (Exception e) {
             fail(e.getMessage());   
         }
     }
	

	/**
	 * Test class to bypass package visibility
	 * @author dchurchett
	 *
	 */
	class TestProtectedResourceWrapper extends ProtectedResourceWrapper {

		@SuppressWarnings("unchecked")
		public TestProtectedResourceWrapper(Class c)
				throws ProtectedResourceNamingException {
			super(c);
		}
	}
 
 
     /**
      * Returns a String representation of a PermissionSet in the form
      * of the XML DTD value (i.e., irwcd)
      */
     private String getPermsAsString(PermissionSet perms) {
 
         char[] charPerms = new char[5];
         charPerms[0] = (perms.canCreate()) ? 'i' : '-';
         charPerms[1] = (perms.canRead()) ? 'r' : '-';
         charPerms[2] = (perms.canWrite()) ? 'w' : '-';
         charPerms[3] = (perms.canControl()) ? 'c' : '-';
         charPerms[4] = (perms.canDelete()) ? 'd' : '-';
 
         return new String(charPerms);
     }
 
     /**
      * Returns a AuthorizationContext object of a TeamLeader and Manager who is
      * also assigned to a Project instance 
      */
     private AuthorizationContext getTeamLeaderContext() throws IllegalAuthorizationException {
 
         String userGUID = "12341234";
         String productID = "991";
         String accountID = "0000001";
 
         List<String> subs = new ArrayList<String>();
         subs.add("991");
         subs.add("992");
         subs.add("993");
 
         List<String> roles = new ArrayList<String>();
         roles.add("manager");
         roles.add("teamleader");
 
         return new DefaultAuthorizationContext(accountID, productID, subs, userGUID, roles);
 
     }
 
     /**
      * Returns a AuthorizationContext object of a Manager
      */
     private AuthorizationContext getManagerContext() throws IllegalAuthorizationException {
 
         String userGUID = "12341234";
         String productID = "991";
         String accountID = "0000001";
 
         List<String> subs = new ArrayList<String>();
         subs.add("991");
         subs.add("992");
         subs.add("993");
 
         List<String> roles = new ArrayList<String>();
         roles.add("manager");
 
         return new DefaultAuthorizationContext(accountID, productID, subs, userGUID, roles);
 
     }
 
 
     /**
      * Returns a AuthorizationContext object of a Participant accessing a product their
      * account is not subscribed to
      */
     private AuthorizationContext getIllegalSubscriptionContext() throws IllegalAuthorizationException {
 
         String userGUID = "11";
         String productID = "991";
         String accountID = "100";
 
         List<String> subs = new ArrayList<String>();
         subs.add("993");
         subs.add("995");
         
         List<String> roles = new ArrayList<String>();
         roles.add("participant");
 
         return new DefaultAuthorizationContext(accountID, productID, subs, userGUID, roles);
 
     }
 
     /**
      * Returns a vendor authenticated as 'test-partner-guid'
      */
     private AuthorizationContext getVendorContext() throws IllegalAuthorizationException {
 
         String userGUID = "test-partner-guid";
         String productID = "993";
         String accountID = "201";
 
         List<String> subs = new ArrayList<String>();
         subs.add("993");
 
         List<String> roles = new ArrayList<String>();
         roles.add("vendor");
 
         return new DefaultAuthorizationContext(accountID, productID, subs, userGUID, roles);
 
     }
 
     /**
      * Creates an AuthorizationContext object for a user with no roles
      */
     private AuthorizationContext getNoRoleContext() throws IllegalAuthorizationException {
 
         String userGUID = "";
         String productID = "";
         String accountID = "";
 
         List<String> subs = new ArrayList<String>();
         subs.add("991");
         List<String> roles = new ArrayList<String>();
 
         return new DefaultAuthorizationContext(accountID, productID, subs, userGUID, roles);
         
     }
 
     /**
      * Creates an AuthorizationContext object for an account with no subscriptions
      */
     private AuthorizationContext getNoSubscriptionsContext() throws IllegalAuthorizationException {
 
         String userGUID = "";
         String productID = "";
         String accountID = "";
 
         List<String> subs = new ArrayList<String>();
         List<String> roles = new ArrayList<String>();
         roles.add("manager");
 
         return new DefaultAuthorizationContext(accountID, productID, subs, userGUID, roles);
         
     }
 
 
     /**
      * Provided for JUnit invocation
      */
     public static void main(String[] args) {
         junit.textui.TestRunner.run(new TestSuite(com.hippikon.security.test.PermsTest.class));
         System.exit(0);
     }
 }

