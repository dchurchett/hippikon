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
 
 import java.io.*;
 import java.util.*;
 import org.apache.log4j.*;
 import com.hippikon.io.FileUtil;
 import org.w3c.dom.*;
import javax.xml.parsers.*;
 
 
 /**
  * The XMLPolicyStore class provides an implementation of a {@link PolicyStore}
  * where permissions for user and roles principals are defined in an XML 
  * file named [productID]-policy-store.xml that must be located in 
  * the system classpath.<p>
  *
  * @author Dale Churchett
  * @version $Id: XMLPolicyStore.java,v 1.6 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 class XMLPolicyStore extends DefaultPolicyStore {
 
     @SuppressWarnings("unused")
	private static int count = 0;
 
     // policy store file prefixes and extensions defined to 
     // avoid duplication and typos
     //
     static final String POLICY_STORE_NODENAME = "policy-store";
     private static final String POLICY_STORE_PREFIX = "hippikon.product-id.";
     private static final String POLICY_STORE_EXT = ".policy-store.xml";
 
     // the name of the protected-resource XML node
     //
     static final String PROTECTED_RESOURCE = "protected-resource";
 
     private static Logger log = Logger.getLogger("com.hippkion.security.XMLPolicyStore");
 
     // ProtectedResource DOM Node->ResourceAclList map
     //
     private Map<Node, ResourceAclList> nodeAclListMap;
 
     // the list of bottom-most ProtectedResource nodes
     // i.e., those that appear last in a resource path
     //
     private List<Node> leafList;
 
     // used to load the XML document for the correct product    
     //
     @SuppressWarnings("unused")
     private String productID;
     private String filename;
     private String applicationName;
     private File xmlFile;
     private Document xmlDoc;
     
     private List<String> uniquePrincipals = new ArrayList<String>();
 
 
     /**
      * Creates a new XMLPolicyStore for a specific product or application.
      *
      * @param productID the identifier for the product being accessed
      * @exception PolicyStoreLoadException thrown if the PolicyStore could
      * not be loaded
      */
     protected XMLPolicyStore(String productID) throws PolicyStoreLoadException {
 
         this.productID = productID;
         this.filename = constructStoreFilename(productID);
 
         // load the data structure from the XML file
         //
         try {
             this.xmlFile = FileUtil.findFileInClasspath(filename);
         } catch (Exception e) {
             throw new PolicyStoreLoadException(e.getMessage());
         }
         load();
     }
 
     // provided for the PermsNavigator
     //
     XMLPolicyStore(File file) throws PolicyStoreLoadException {
         log.debug("Loading XML file:" + file);
         this.xmlFile = file;
         load();
     }
 
     /**
      * Returns the application name of the XML policy file
      */
     protected String getApplicationName() {
         return applicationName;
     }
 
     /**
      * Returns the correct filename convention for a storeID. Account
      * policy store files are named by the [accountID].policy-store.xml
      * while product policy store files are named SAL-PRDT-([\d]{3}).policy-store.xml
      * (e.g. SAL-PRDT-001.policy-store.xml)
      */
     private String constructStoreFilename(String productID) {
 
         // check for policy stores containing account
         // specific extensions. These will start with SAL
         //
         return POLICY_STORE_PREFIX + zeroPadProductID(productID) + POLICY_STORE_EXT;
          
     }
     
     /**
      * Returns the Document object for the loaded xml policy file
      * provided for the perms navigator
      *
      * @return Document
      * @exception IllegalStateException thrown if the xml document has not been loaded
      */
     Document getDocument() throws PolicyStoreLoadException {
         if (xmlDoc == null) {
             throw new PolicyStoreLoadException("XML Document has not been initialized");
         }
         return xmlDoc;
     }
     
 
     /**
      * Returns a 3-length String zero padded productID (e.g., 001, 002)
      */
     private String zeroPadProductID(String productID) {
         StringBuffer sb = new StringBuffer();
         for (int i = (3 - productID.length()); i > 0; i--) {
             sb.append("0");
         }
         sb.append(productID);
         return sb.toString();
     }
 
 
     /**
      * Load the PolicyStore from an XML file
      */
     protected void load() throws PolicyStoreLoadException {
 
         try {
 
             // used to store the nodes and their corresponding ResourceAclList
             //
             this.nodeAclListMap = new HashMap<Node, ResourceAclList>();
             this.leafList = new ArrayList<Node>();
     
             String xmlFilename = this.xmlFile.getAbsolutePath();
         
             // read and parse the XML file as a DOM object
             //
             DocumentBuilder domParser = DocumentBuilderFactory.newInstance().newDocumentBuilder();
             File xmlFile = new File(xmlFilename);
             this.xmlDoc = domParser.parse(xmlFile);
             xmlFile = null;
 
             // get the root element, which is the product itself
             //
             //Document xmlDoc = domParser.getDocument();
             Element prdNode = xmlDoc.getDocumentElement();
 
             this.applicationName = prdNode.getAttribute("application-name");
             log.debug("Parsing XML Policy Store for product: " + applicationName);
 
             // get all the protected-resource entries and map their respective
             // ResourceAclList objects to the DOM node from the XML document
             //
             NodeList allResNodes = xmlDoc.getElementsByTagName(PROTECTED_RESOURCE);
             for (int j = 0; j < allResNodes.getLength(); j++) {
                 Node node = allResNodes.item(j);
 
                 ResourceAclList resAclList = getAclListForNode(node);
                 nodeAclListMap.put(node, resAclList);
 
                 // keep track of leaf nodes so we can work backwards later
                 //
                 if (!(hasChildProtectedResource(node))) {
                     leafList.add(node);
                 }
             }
 
             // now we can recurse through the bottom nodes
             // and build the tree
             //
             for (Iterator<Node> i = leafList.iterator(); i.hasNext();) {
                 Node node = (Node)i.next();
                 buildTree(node);
             }
 
             // now we can add the top-level nodes to the 
             // data structure defined in the superclass
             //
             NodeList resNodes = prdNode.getChildNodes();
             for (int i = 0; i < resNodes.getLength(); i++) {
                 Node node = resNodes.item(i);
                 if (node.getNodeType() == Node.COMMENT_NODE) {
                     continue;
                 }
                 ResourceAclList aclList = (ResourceAclList)nodeAclListMap.get(node);
                 if (!(node instanceof Element)) continue;
                 Element e = (Element)node;
                 String key = e.getAttribute("name");
                 addResourceAclList(key, aclList);
             }
 
         } catch (Exception e) {
             e.printStackTrace();
             System.exit(0);
             throw new PolicyStoreLoadException(e.getMessage());
         }
     }
 
     /**
      * Builds a tree of ResourceAclList objects working backwards
      * through the DOM object. This is a recursive method.
      */
     private void buildTree(Node node) {
         ResourceAclList aclList = (ResourceAclList)nodeAclListMap.get(node);
 
         Node parentNode = node.getParentNode();
         if (parentNode.getNodeName().equals(POLICY_STORE_NODENAME) || !parentNode.getNodeName().equals(PROTECTED_RESOURCE)) {
             return;
         } 
         ResourceAclList parentAclList = (ResourceAclList)nodeAclListMap.get(parentNode);
         parentAclList.addNestedList(aclList);
         buildTree(parentNode);
     }
 
     /**
      * Returns true if a node has a ProtectedResource as a child
      * node
      */
     private boolean hasChildProtectedResource(Node node) {
 
         boolean hasChild = false;
         Element e = (Element)node;
         @SuppressWarnings("unused")
		String nodeName = node.getNodeName();
         NodeList elementNodes = e.getChildNodes();
         for (int i = 0; i < elementNodes.getLength(); i++) {
             Node childNode = elementNodes.item(i);
             if (childNode.getNodeName() == PROTECTED_RESOURCE) {
                 hasChild = true;
                 break;
             }
         }
         return hasChild;
     }
 
 
     /**
      * Returns a ResourceAclList object for a node
      * representing a ProtectedResource
      *
      * Nodes that have no user, role or child
      * protected-resource nodes defined inherit
      * all permissions from their parent - to ensure
      * no NULLs are returned we create the ResourceAclList
      * object first and add when we find user and role
      * permissions
      *
      */
     private ResourceAclList getAclListForNode(Node node) {
 
         Element el = (Element)node;
         @SuppressWarnings("unused")
		 String nodeName = node.getNodeName();
         String resourceName = el.getAttribute("name");
         ResourceAclList aclList = new ResourceAclList(resourceName);
 
         // now find the role, user and any nested entries
         //
         NodeList elementNodes = el.getChildNodes();
         for (int i = 0; i < elementNodes.getLength(); i++) {
 
             Node childNode = elementNodes.item(i);
             String elementName = childNode.getNodeName();
 
             // ignore comments
             //
             if (childNode.getNodeType() == Node.COMMENT_NODE) {
                 continue;
             }
 
             // here we will have nested resources
             //
             if (childNode.getNodeName().equals(PROTECTED_RESOURCE)) {
                 continue;
             }
 
             if (!(childNode instanceof Element)) continue;
             Element childElement = (Element)childNode;
             String acl = childElement.getAttribute("acl");
             int aclIntVal = DefaultPermissionSet.getIntVal(acl);
 
             String childNodeName = childNode.getNodeName();
             if ((childNodeName != null) && childNodeName.equals("principal")) {
                 String principalName = childElement.getAttribute("name");
                 aclList.addPrincipalACL(new ACL(principalName, aclIntVal));
                 
                 // keep a running list of all unique principals
                 // primarily used in the PermissionsNavigator UI tool
                 //
                 if (!uniquePrincipals.contains(principalName)) {
                     uniquePrincipals.add(principalName);
                 }
                 log.debug("Defining ACL for " + resourceName + "> " + elementName + ":" + principalName + ":" + acl + " (" + aclIntVal + ")");
             } else {
                 continue;
             }
         }
 
         return aclList;
     }
     
     public List<String> getDefinedPrincipals() {
         return uniquePrincipals;
     }
 
 }

