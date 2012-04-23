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
import org.w3c.dom.*;

import javax.swing.tree.DefaultMutableTreeNode;
import javax.xml.transform.*;
import javax.xml.parsers.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;


/**
 * Transforms a JTree into an XML document and writes out to a File
 *
 * @author Dale Churchett
 * @version $Id: JTreeXMLTransformer.java,v 1.4 2012/04/23 14:25:16 dalehippikon Exp $
 * @since JDK 1.4
 */
public class JTreeXMLTransformer {
    
    private File file;
    private DefaultMutableTreeNode top;
    private Element root;
    
    private Map<DefaultMutableTreeNode, Element> treeNodeToElementMap;
    
    /** 
     * Creates a new instance of JTreeXMLTransformer 
     *
     * @param file the File to write the XML out to
     * @param top the root node of the JTree to write out
     */
    public JTreeXMLTransformer(File file, DefaultMutableTreeNode top) {
        this.file = file;
        this.top = top;
        this.treeNodeToElementMap = new HashMap<DefaultMutableTreeNode, Element>();
    }
    
    
    // converts the current tree model into an XML policy store format
    //
    @SuppressWarnings("unchecked")
	public int saveToFile() throws Exception {
        
        Document newDoc = initDocument();
        
        // create an XML element for every node in the TreeModel - at 
        // this time we do not try to correlate the two together
        //
        Enumeration e = top.preorderEnumeration();
        J:while (e.hasMoreElements()) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode)e.nextElement();
            if (node.isRoot()) 
                continue J;
            Element element = createElement(newDoc, node);
            treeNodeToElementMap.put(node, element);
            populateMap(newDoc, node);
        }
         
        // now we have built up the Map of Node->Elements for the entire tree,
        // we can go through the top level nodes, finding each child in turn
        // and associating parent nodes to parent Elements, this way we
        // build up a XML Document object ready to write out to a file
        //
        e = top.preorderEnumeration();
        M:while (e.hasMoreElements()) {
            
            DefaultMutableTreeNode node = (DefaultMutableTreeNode)e.nextElement();
            Element childElement = (Element)treeNodeToElementMap.get(node); 
            DefaultMutableTreeNode parentNode = (DefaultMutableTreeNode)node.getParent();
            
            // if the parentNode is the root then make sure to add the association
            // for the top level - without this we will have broken links to children
            //
            if (parentNode == null) {
                continue M;
            }
            if (parentNode.isRoot()) {
                root.appendChild(childElement);
                continue M;
            }
            // if we get here we are simply adding a child node to a parent node
            // that is not the root node
            //
            Element parentElement = (Element)treeNodeToElementMap.get(parentNode);
            parentElement.appendChild(childElement);  
            buildElements(newDoc, node);
        }        
  
        return writeFile(newDoc);
    } 
    
    
    
    // recursively populates a Map of TreeNode->Element
    //
    private void populateMap(Document newDoc, DefaultMutableTreeNode node) {
        int childCount = node.getChildCount();
        for (int i = 0; i < childCount; i++) {
            DefaultMutableTreeNode childNode = (DefaultMutableTreeNode)node.getChildAt(i);
            Element childElement = createElement(newDoc, childNode);
            treeNodeToElementMap.put(childNode, childElement);
            populateMap(newDoc, childNode);
        }  
    } 
    
    
    // recursively builds the parent element->child element structure ready for
    // XML dump to file
    //
    private void buildElements(Document newDoc, DefaultMutableTreeNode node) {
        int childCount = node.getChildCount();
        for (int i = 0; i < childCount; i++) {
            DefaultMutableTreeNode childNode = (DefaultMutableTreeNode)node.getChildAt(i);
            Element childElement = (Element)treeNodeToElementMap.get(node); 
            DefaultMutableTreeNode parentNode = (DefaultMutableTreeNode)node.getParent();
            Element parentElement = (Element)treeNodeToElementMap.get(parentNode);
            parentElement.appendChild(childElement); 
            buildElements(newDoc, childNode);
        }
    } 
   
     
    /**
     * Creates the new Document and starts off with the top most node
     * while initializing the root element
     *
     * @return a new Document object with valid root node
     *
     * @exception Exception thrown if the Document could not be initialized
     */
    public Document initDocument() throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document newDoc = builder.newDocument();
        
        // create the top node and add to the new document
        //
        // TODO: make these parameters to allow for greater re-use outside of Hippikon
        //
        this.root = newDoc.createElement(XMLPolicyStore.POLICY_STORE_NODENAME);
        root.setAttribute("application-name", top.toString());
        newDoc.appendChild(root);
        
        treeNodeToElementMap.put(top, root);
        
        return newDoc;
    }
     
    // given a TreeNode from a JTree, create an XML Element 'protected-resource'
    // setting the 'name' attribute to the node name and converting the userObject
    // ResourceAclList into a child Element appended to the node Element
    //
    private Element createElement(Document newDoc, DefaultMutableTreeNode node) {

        Element childElement = newDoc.createElement(XMLPolicyStore.PROTECTED_RESOURCE);
        childElement.setAttribute("name", node.toString());
        ResourceAclList resList = (ResourceAclList)node.getUserObject();
        Collection<ACL> acls = resList.getAcls();
        for (Iterator<ACL> i = acls.iterator(); i.hasNext();) {
            ACL acl = (ACL)i.next();
            Element aclElement = newDoc.createElement("principal");
            aclElement.setAttribute("name", acl.getName());
            aclElement.setAttribute("acl", new DefaultPermissionSet(acl.getPermsAsInt()).toString());
            childElement.appendChild(aclElement);
        }
        return childElement;
    }
    
    
    // does the business of writing out the XML Document to 
    // a File object
    // returns a 1 if sucessful or an Exception if not
    //
    private int writeFile(Document newDoc) throws Exception {
        FileWriter out = null;
        try {
            // Use a Transformer for output
            //
            TransformerFactory tFactory = TransformerFactory.newInstance();
            Transformer transformer = tFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.ENCODING,"ISO-8859-1");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            
            DOMSource source = new DOMSource(newDoc);
            out = new FileWriter(file);
            StreamResult result = new StreamResult(out);
            transformer.transform(source, result);
            out.flush();
            
        } finally {
             try {
                if (out != null) out.close();
             } catch (IOException ioe) { 
                 System.err.println("WARNING: Error closing file handles");
             }
          }
        return 1;
    }

}
