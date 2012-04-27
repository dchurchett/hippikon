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
 

 import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.DefaultCellEditor;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToolBar;
import javax.swing.JTree;
import javax.swing.ListSelectionModel;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.MutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import org.w3c.dom.Document;
 
 /**
  * PermsNavigator provides a Swing GUI that displays an XML Policy Store
  * defined for an application. It presents the legal object hierarchy
  * as a JTree and calculates the permissions for all principals for 
  * any given object in the tree.<p>
  *
  * The permissions are displayed in a JTable and combine the total permissions
  * for the principal for the resource path being viewed. The tool can easily
  * accommodate future PolicyStore implementations and dynamic lookup of 
  * products.<p>
  *
  * @author Dale Churchett
  * @version $Id: PermsNavigator.java,v 1.18 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
public class PermsNavigator extends JFrame {
 
 
	private static final long serialVersionUID = -6210181983693437751L;
	
	private JTree tree;
	private JPopupMenu popup;
	private JTextArea resPathTextArea;
	private DefaultTableModel tableModel;
	private JFileChooser fc;
	private static final String NL = System.getProperty("line.separator");
	private PolicyStore store = null;
	private Map<String, ResourceAclList> topResAcls = null;
	@SuppressWarnings("unused")
	private Document xmlDoc;
	private DefaultTreeModel treeModel;
	private DefaultMutableTreeNode top = null;
	private JTable table = null;
	private ResourceAclList currentResAcl;
	@SuppressWarnings("unused")
	private File currentFile = null;
	private JButton saveBtn;
     

     /**
      * Creates the main GUI and initializes all components
      */
     private PermsNavigator() {
 
         super(" Hippikon Permissions Navigator");
         setSize(700, 630);
         addWindowListener(new WindowAdapter() {
             public void windowClosing(WindowEvent e) {
                 System.exit(0);
             }
         });
         
         // setup the popup menu and items
         //
         popup = new JPopupMenu();
         
         JMenuItem addNode = new JMenuItem("Add Node");
         popup.add(addNode);
         addNode.addActionListener(new ActionListener() {
             public void actionPerformed(ActionEvent e) {
                 
                 DefaultMutableTreeNode parentNode = null;
                 TreePath currentSelection = tree.getSelectionPath();
                 
                 if (currentSelection != null) {
                     parentNode = (DefaultMutableTreeNode)(currentSelection.getLastPathComponent());
                 } else {
                     parentNode = top;
                 }
                  
                 // create a new default node that the user should edit
                 //
                 DefaultMutableTreeNode childNode = new DefaultMutableTreeNode("ProtectedResource");
                 
                 // add the nested resource list from the parent node provided
                 // it is not the root of the tree
                 //
                 ResourceAclList resList = new ResourceAclList("ProtectedResource");
                 if (!parentNode.isRoot()) {
                    ResourceAclList parentList = (ResourceAclList)parentNode.getUserObject();
                    resList.addNestedList(parentList);
                 }

                 if (parentNode == null) {
                     parentNode = new DefaultMutableTreeNode(top.toString());
                 }
                 
                 // we create a default resourceAclList for new nodes then make
                 // the parent/child association
                 //
                 childNode.setUserObject(resList);
                 treeModel.insertNodeInto(childNode, parentNode, parentNode.getChildCount());

                 //Make sure the user can see the lovely new node.
                 //
                 TreePath newPath = new TreePath(childNode.getPath());
                 tree.scrollPathToVisible(newPath);
                 
                 // automatically prompt the user to start editing the new node
                 //
                 tree.startEditingAtPath(newPath);
             }
         });
         
         JMenuItem removeNode = new JMenuItem("Remove Node");
         popup.add(removeNode);
         removeNode.addActionListener(new ActionListener() {
             public void actionPerformed(ActionEvent e) {
                 TreePath currentSelection = tree.getSelectionPath();
                 if (currentSelection != null) {
                    DefaultMutableTreeNode currentNode = (DefaultMutableTreeNode)(currentSelection.getLastPathComponent());
                    MutableTreeNode parent = (MutableTreeNode)(currentNode.getParent());
                    if (parent != null) {
                        treeModel.removeNodeFromParent(currentNode);
                        currentNode.setUserObject(null);
                        return;
                    }
                }
             }
         });
         
         // renames the currently selected node and the underlaying user object (ResourceAclList)
         //
         JMenuItem renameNode = new JMenuItem("Rename Node");
         popup.add(renameNode);
         renameNode.addActionListener(new ActionListener() {
             public void actionPerformed(ActionEvent e) {
                 @SuppressWarnings("unused")
				DefaultMutableTreeNode node = (DefaultMutableTreeNode)tree.getLastSelectedPathComponent();
                 tree.startEditingAtPath(tree.getSelectionPath());
             }
         });
         
 
         // set up the menu bar and items
         //
         JMenuBar menuBar = new JMenuBar();
         JMenu prdtMenu = new JMenu("File");
         menuBar.add(prdtMenu);
         JMenuItem createItm = new JMenuItem("New Policy Store");
         JMenuItem loadItm = new JMenuItem("Load Policy Store");
         JMenuItem saveItm = new JMenuItem("Save Store As");
         fc = new JFileChooser();
         fc.setFileFilter(new XMLFileFilter());
         
         // add the option to create a new store
         //
         createItm.addActionListener(new CreateAction());
         prdtMenu.add(createItm);
 
         // add the listener to load a xml file from disk
         //
         loadItm.addActionListener(new LoadAction());
         prdtMenu.add(loadItm);
         
         // add the ability to save the file to disk
         // as a new policy store file
         //
         saveItm.addActionListener(new SaveAction());
         prdtMenu.add(saveItm);
         
         // now add the main exit item
         //
         JSeparator separator = new JSeparator();
         prdtMenu.add(separator);
         JMenuItem exitItm = new JMenuItem("Exit");
         exitItm.addActionListener(new ActionListener() {
             public void actionPerformed(ActionEvent e) {
                Object[] options = {"Exit","Don't Exit"};
                int n = JOptionPane.showOptionDialog(null, "Exiting will lose any unsaved changes to the current store!",
                            "Exit Confirmation", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE,
                            null, options, options[1]); //default button title
                 if (n == 0) {
                    System.exit(0);
                 }
             }
         });
         prdtMenu.add(exitItm);
 
         setJMenuBar(menuBar);
 
         // set up the JTree
         //
         DefaultMutableTreeNode top = new DefaultMutableTreeNode("Product Name");
         this.tree = new JTree(top);
         
         // setup the Tree with custom icon, disabled until a new store is created
         // or an existing one is loaded
         //
         ImageIcon leafIcon = getImage("img/leaf.gif");
         DefaultTreeCellRenderer renderer = new DefaultTreeCellRenderer();
         renderer.setLeafIcon(leafIcon);
         renderer.setOpenIcon(leafIcon);
         renderer.setClosedIcon(leafIcon);
         tree.setCellRenderer(renderer);
         tree.putClientProperty("JTree.lineStyle", "Angled");
         tree.setEditable(false);
         tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
 
         // add the listener to detect changes in selection
         //
         tree.addTreeSelectionListener(new TreeSelectionListener() {
             public void valueChanged(TreeSelectionEvent e) {

                 DefaultMutableTreeNode node = (DefaultMutableTreeNode)tree.getLastSelectedPathComponent();
                 
                 // keep a pointer to the current resource ACL object
                 // this is a workaround because the TreeListener that is supposed to handle
                 // node renames seems to reset the node userObject to the name of the 
                 // object rather than actually preserving the userObject reference
                 // itself
                 // also disable the table if the user has selected a node as
                 // they can't add principals at the top level node
                 //
                 if (node != null && node.isRoot()) {
                     clearPermissions();
                     table.setEnabled(false);
                     return;
                 } 
                 
                 // if the user has selected the non-root node then
                 // enable the table for editing
                 //
                 if (!table.isEnabled()) {
                     table.setEnabled(true);
                 }
                 
                 if (node != null) {
                    currentResAcl = (ResourceAclList)node.getUserObject();
                 } else {
                     return;
                 }

                 TreeNode[] nodesInPath = node.getPath();
 
                 // makes sure the principals are in a deterministic order
                 // so users don't get confused
                 //
                 TreeMap<String, ACL> principals = new TreeMap<String, ACL>();
 
                 // construct the resource path name to display
                 //
                 String pathDivider = " / ";
                 StringBuffer sb = new StringBuffer();
                 for (int i = 1; i < nodesInPath.length; i++) {
                     sb.append(nodesInPath[i]);
                     sb.append(pathDivider);
                 }
                 String pathName = sb.toString().substring(0, (sb.toString().length() - pathDivider.length()));
 
                 // builds the principals list for the object hierachy
                 //
                 for (int i = nodesInPath.length-1; i > 0; i--) {
                     DefaultMutableTreeNode n = (DefaultMutableTreeNode)nodesInPath[i];
                     ResourceAclList ral = (ResourceAclList)n.getUserObject();
                     Collection<ACL> acls = ral.getAcls();
                     for (Iterator<ACL> k = acls.iterator(); k.hasNext();) {
                         ACL acl = (ACL)k.next();
                         if (!principals.containsKey(acl.getName())) {
                             principals.put(acl.getName(), acl);
                         }
                     }
                 }
 
                 clearPermissions();
 
                 resPathTextArea.append(pathName);
 
                 // update the table checkboxes to reflect the principal ACLs for
                 // the selected tree node
                 //
                 Collection<ACL> values = principals.values();
                 int count = 0;
                 for (Iterator<ACL> j = values.iterator(); j.hasNext();) {
                     ACL acl = (ACL)j.next(); 
                     DefaultPermissionSet perms = new DefaultPermissionSet(acl.getPermsAsInt());
                     tableModel.setValueAt(acl.getName(), count, 0);
                     tableModel.setValueAt(new Boolean(perms.canCreate()), count, 1); 
                     tableModel.setValueAt(new Boolean(perms.canRead()), count, 2);
                     tableModel.setValueAt(new Boolean(perms.canWrite()), count, 3);
                     tableModel.setValueAt(new Boolean(perms.canControl()), count, 4);
                     tableModel.setValueAt(new Boolean(perms.canDelete()), count, 5);
                     count++;
                 }
             }
         });
         
         // add the popup menu to the tree
         //
         MouseListener popupListener = new PopupListener();
         tree.addMouseListener(popupListener);
 
         // now set up the viewport
         //
         JScrollPane treeView = new JScrollPane(tree);
 
         // set up the permissions panels - permsPanel is the irwcd row
         // subPermsPanels are the individual role panels
         //
         JPanel permsPanel = new JPanel();
         permsPanel.setLayout(new BorderLayout(5,5));
 
         
         // lblPnl has a text area added to it that displays
         // the resource path name
         //
         JPanel lblPnl = new JPanel();
         lblPnl.setLayout(new BorderLayout(5,5));
         lblPnl.setBorder(BorderFactory.createTitledBorder("Resource Path"));
         resPathTextArea = new JTextArea();
         resPathTextArea.setEditable(false);
         resPathTextArea.setFont(new Font("Arial", Font.BOLD, 12));
         resPathTextArea.setBackground(lblPnl.getBackground());
         lblPnl.add(resPathTextArea);
 
         permsPanel.add(lblPnl, BorderLayout.NORTH);
 
         // permsDisplayPnl has a text area that displays the 
         // principal-acl values from the resource path combination
         //
         JPanel permsDisplayPnl = new JPanel();
         permsDisplayPnl.setLayout(new BorderLayout(5,5));
         permsDisplayPnl.setBorder(BorderFactory.createTitledBorder("Permissions"));
 
         // set up the table and table model
         //
         String[] colNames = new String[] { "Principal", "i", "r", "w", "c", "d" };
         tableModel = new PermissionsTableModel(colNames, 20, false);
         table = new JTable(tableModel);
         table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
         
         // setup a custom editor to handle duplicate entries into the 
         // resource acl list by users
         //
         TableColumn principalColumn = table.getColumnModel().getColumn(0);
         JTextField principalTxt = new JTextField(10);
         DefaultCellEditor ce = new DefaultCellEditor(principalTxt);
         principalColumn.setCellEditor(ce);
         ce.addCellEditorListener(new CellEditorListener() {
             public void editingCanceled(ChangeEvent e) {
                 checkDuplicatePrincipals(e);
             }
             public void editingStopped(ChangeEvent e) {
                 checkDuplicatePrincipals(e);
             }
         });
 
         // set the preferred sizes for the columns
         //
         table.getColumnModel().getColumn(0).setPreferredWidth(200);
         for (int i = 1; i < colNames.length; i++) {
             TableColumn c = table.getColumnModel().getColumn(i);
             c.setPreferredWidth(10);
         }

         JScrollPane tableScrollPane = new JScrollPane(table);
         table.setPreferredScrollableViewportSize(new Dimension(500, 70));
         permsDisplayPnl.add(tableScrollPane);
 
         // now add the entire panel to the main right panel
         //
         permsPanel.add(permsDisplayPnl, BorderLayout.CENTER);
 
         // infoPnl contains the legend for each permission
         //
         JPanel infoPnl = new JPanel();
         infoPnl.setBorder(BorderFactory.createTitledBorder("Legend"));
         infoPnl.setLayout(new BorderLayout(5,5));
         JTextArea infoTxt = new JTextArea();
         infoTxt.setBackground(infoPnl.getBackground());
         infoTxt.append(" i - Can instantiate / create" + NL);
         infoTxt.append(" r - Can read" + NL);
         infoTxt.append(" w - Can write/edit" + NL);
         infoTxt.append(" c - Can control / change state" + NL);
         infoTxt.append(" d - Can delete" + NL);
         infoPnl.add(infoTxt);
         permsPanel.add(infoPnl, BorderLayout.SOUTH);
 
         // set up the split pane view
         //
         JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeView, permsPanel);
         splitPane.setOneTouchExpandable(true);
         splitPane.setDividerLocation(230);
         Dimension minimumSize = new Dimension(180, 500);
         treeView.setMinimumSize(minimumSize);
         
         // this is how we can open up the editor in read-only mode
         // the state is changed using the Read-Only checkbox in the editor
         //
         table.setEnabled(false);
         
         // create the toolbar
         //
         JToolBar toolBar = new JToolBar("Hippikon");
         JButton newBtn = makeButton("img/new24.gif", "New XML Policy Store", "New Policy Store");
         newBtn.addActionListener(new CreateAction());
         toolBar.add(newBtn);
         JButton openBtn = makeButton("img/open24.gif", "Load XML File", "Load XML File");
         openBtn.addActionListener(new LoadAction());
         toolBar.add(openBtn);
         saveBtn = makeButton("img/save24.gif", "Save As", "Save File As");
         saveBtn.addActionListener(new SaveAction());
         saveBtn.setEnabled(false);
         toolBar.add(saveBtn);
         getContentPane().add(toolBar, BorderLayout.PAGE_START);
         
         // add the split pane and all contents to the navigator
         //
         getContentPane().add(splitPane);
         setVisible(true);
     }
 
 
     // builds up the tree nodes from the policy store
     // data structure using a recursive algorithm
     //
     private void createNodes(File f) {
        top = null;
         try {
 
             // load and parse the file or present an error dialog to the user
             // so the whole app does not croak
             // 
             try {
                    
                 this.currentFile = f;
                 this.store = new XMLPolicyStore(f);
                 this.xmlDoc = ((XMLPolicyStore)store).getDocument();
                 this.topResAcls = ((DefaultPolicyStore)store).getResourceAcls();
                 currentResAcl = null;
                 
                 // now we can put the editor into the active state
                 // as we have a store loaded up
                 //
                 tree.setEnabled(true);
                 tree.setEditable(true);
                 saveBtn.setEnabled(true);
                 
             } catch (PolicyStoreLoadException pe) {
                 JOptionPane.showMessageDialog(this, "Could not parse XML policy file");
                 return;
             }
 
             // set up the TreeModel for the tree
             //
             top = new DefaultMutableTreeNode(((XMLPolicyStore)store).getApplicationName());
             treeModel = new DefaultTreeModel(top);
             treeModel.addTreeModelListener(new ResourceTreeModelListener());
             tree.setModel(treeModel);
 
             // recursively add children
             //
             Collection<ResourceAclList> topResKeys = topResAcls.values();
             for (Iterator<ResourceAclList> i = topResKeys.iterator(); i.hasNext();) {
                 ResourceAclList resAcl = (ResourceAclList)i.next();
                 DefaultMutableTreeNode node = new DefaultMutableTreeNode(resAcl);
                 top.add(node);
                 addChildNode(node, resAcl);
             }
            
         } catch (Exception e) {
             e.printStackTrace();
             return;
         }
         table.setEnabled(false);
         tree.expandRow(0);  
     }
     
 
     // recursively builds up child nodes using a parent TreeNode and an 
     // associated ResourceAclList that contains children
     //
     private void addChildNode(DefaultMutableTreeNode parentNode, ResourceAclList aclList) {
         Map<String, ResourceAclList> childResAcls = aclList.getNestedList();
         Collection<ResourceAclList> c = childResAcls.values();
         for (Iterator<ResourceAclList> j = c.iterator(); j.hasNext();) {
             ResourceAclList aL = (ResourceAclList)j.next();
             DefaultMutableTreeNode child = new DefaultMutableTreeNode(aL);
             parentNode.add(child);
             addChildNode(child, aL);
         }
     }
 
 
     // clear the GUI of any permissions already being displayed in the JTable
     //
     private void clearPermissions() {
         resPathTextArea.setText("");
         for (int i = 0; i < tableModel.getRowCount(); i++) {
             tableModel.setValueAt("", i, 0);
             tableModel.setValueAt(new Boolean(false), i, 1);
             tableModel.setValueAt(new Boolean(false), i, 2);
             tableModel.setValueAt(new Boolean(false), i, 3);
             tableModel.setValueAt(new Boolean(false), i, 4);
             tableModel.setValueAt(new Boolean(false), i, 5);
         }
     }
     
     // loads up the ImageIcon from the JAR file
     //
      private ImageIcon getImage(String name) {
         try {
             ClassLoader cldr = this.getClass().getClassLoader();
             java.net.URL imageURL = cldr.getResource(name);
             return new ImageIcon(imageURL);
         } catch (Exception e) {
             System.err.println("Error loading image icon from JAR file");
             e.printStackTrace();
             return null;
         }     
      }
    

 
     // A file filter for XML files to be installed in a JFileChooser component
     //
     private class XMLFileFilter extends javax.swing.filechooser.FileFilter {
 
         public boolean accept(File f) {
             if (f.isDirectory()) return true;
 
             String extension = getExtension(f);
             if (extension != null) {
                 if (extension.equals("xml"))
                     return true;
                 else
                     return false;
             }
             return false;
         }
 
         public String getDescription() {
             return "XML Files (*.xml)";
         }
 
         private String getExtension(File f) {
             String ext = null;
             String s = f.getName();
             int i = s.lastIndexOf('.');
             if (i > 0 && i < s.length() - 1) {
                 ext = s.substring(i+1).toLowerCase();
             }
             return ext;
         }
     }
      
   
    // handles pop-up menu events for the JTree
    //
    private class PopupListener extends MouseAdapter {
        public void mousePressed(MouseEvent e) {
            maybeShowPopup(e);
        }
        public void mouseReleased(MouseEvent e) {
            maybeShowPopup(e);
        }
        private void maybeShowPopup(MouseEvent e) {
            if (e.isPopupTrigger()) {
                JTree jt = (JTree)e.getComponent();
                if (jt.getLastSelectedPathComponent() == null) {
                    return;
                }
                if (store == null) 
                    return;
                @SuppressWarnings("unused")
				DefaultMutableTreeNode node = (DefaultMutableTreeNode)tree.getLastSelectedPathComponent();
                popup.show(tree, e.getX(), e.getY());
            }
        }
    }
   
    // makes up a JButton for the toolbar
    //
    private JButton makeButton(String imageName, String actionCommand, String toolTipText) {
        ImageIcon icon = getImage(imageName);
        JButton button = new JButton();
        button.setActionCommand(actionCommand);
        button.setToolTipText(toolTipText);
        button.setIcon(icon);
        return button;
    }
    

    // constructs the ResourceAclList for the currently selected
    // node in the JTree based on the user input from the populated JTable
    // this method will completely wipe out the existing userObject
    // and create the 'truth'
    //
    @SuppressWarnings("unchecked")
	private void buildResourceAcls() {
        PermissionsTableModel model = (PermissionsTableModel)table.getModel();
        TreePath path = tree.getSelectionPath();
        if (path == null) 
            return;
        DefaultMutableTreeNode node = (DefaultMutableTreeNode)path.getLastPathComponent();
        if (node.isRoot()) {
            return;
        }
        int rowCount = model.getRowCount();
        if (store == null) return;
        
        // get the user object resourceAclList we are going to 
        // replace ACLs for as we go
        //
        ResourceAclList resList = (ResourceAclList)node.getUserObject();
        resList.clearPrincipalACLs();
        
        for (int r = 0; r < rowCount; r++) {
            java.util.List list = model.getRow(r);
            
            String principal = (String)list.get(0);
            String iFlag = (String)list.get(1);
            String rFlag = (String)list.get(2);
            String wFlag = (String)list.get(3);
            String cFlag = (String)list.get(4);
            String dFlag = (String)list.get(5);
            if (principal == null || principal.equals("")) {
                return;
            }
            MutablePermissionSet perms = new MutablePermissionSet();
            if (iFlag.equals("true")) perms.setCreateFlag();
            if (rFlag.equals("true")) perms.setReadFlag();
            if (wFlag.equals("true")) perms.setWriteFlag();
            if (cFlag.equals("true")) perms.setControlFlag();
            if (dFlag.equals("true")) perms.setDeleteFlag();
            
            ACL acl = new ACL(principal, perms.getIntValue());
            resList.addPrincipalACL(acl);
            //System.out.println("Principal: " + principal + ", i: " 
            // + iFlag + ", r: " + rFlag + ", w:" + wFlag + ", c: " + cFlag + ", d: " + dFlag);
        }

    }
         
    // checks for any duplicate principals entered into the JTable
    // and warns the user if so
    //
    private void checkDuplicatePrincipals(ChangeEvent e) {

        DefaultCellEditor editor = (DefaultCellEditor)e.getSource();
        JTextField txtField = (JTextField)editor.getComponent();
        String newPrincipal = txtField.getText();

        // detect for duplicate entries in the scope of the
        // permissions pane as this is not allowed
        //
        Map<String, Integer> principals = new HashMap<String, Integer>();
        for (int i = 0; i < table.getModel().getRowCount(); i++) {
            String p = (String)table.getModel().getValueAt(i, 0);
            if (p == null || p.equals("")) {
                continue;
            }
            Integer count = (Integer)principals.get(p);
            if (count == null) {
                count = new Integer(0);
            }
            principals.put(p, new Integer(count.intValue() + 1));
        }
        boolean duplicate = false;
        for (Iterator<Integer> it = principals.values().iterator(); it.hasNext();) {
            Integer i = (Integer)it.next();
            if (i.intValue() > 1) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            JOptionPane.showMessageDialog(null, "Duplicate principal detected: " + newPrincipal, "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
           
     
    // provides the table model that ensures JCheckBox is used for Boolean values
    // why Swing doesn't default to this behaviour is beyond me
    //
    class PermissionsTableModel extends DefaultTableModel {
        
		private static final long serialVersionUID = -1679683041236695622L;
		private String[] columnNames;
        private Object[][] data;
        private int cols;
        
        // init the data structure for the model
        //
        PermissionsTableModel(String[] colNames, int cols, boolean storeLoaded) {
            super(colNames, cols);
            this.columnNames = colNames;
            this.cols = cols;
            this.data = new Object[cols][colNames.length];
            for (int i = 0; i < cols; i++) {
                data[i][0] = "";
            }
            for (int i = 0; i < cols; i++) {
                for (int j = 1; j < colNames.length; j++) {
                    if (storeLoaded) {
                        data[i][j] = new Boolean(false);
                    } else {
                        data[i][j] = "";
                    }
                }
            }
        }

        public int getColumnCount() {
            return columnNames.length;
        }

        public int getRowCount() {
            return cols;
        }

        public String getColumnName(int col) {
            return columnNames[col];
        }

        public Object getValueAt(int row, int col) {
            return data[row][col];
        }

        /*
         * JTable uses this method to determine the default renderer/
         * editor for each cell.  If we didn't implement this method,
         * then the last column would contain text ("true"/"false"),
         * rather than a check box.
         */
        public Class<?> getColumnClass(int c) {
            return getValueAt(0, c).getClass();
        }

        public boolean isCellEditable(int row, int col) {
            return true;
        }

        // record the change in value and update the resourceACL permissions
        // mapping to selected node accordingly
        //
        public void setValueAt(Object value, int row, int col) {
            
            // if a store has not beel loaded don't attempt to 
            // change anything or we'll get a NullPointerException
            //
            if (store == null) {
                return;
            }
                       
            boolean debug = false;
            if (debug) {
                System.out.println("Setting value at " + row + "," + col
                                   + " to " + value
                                   + " (an instance of "
                                   + value.getClass() + ")");
            }

            data[row][col] = value;
            fireTableCellUpdated(row, col);

            if (debug) {
                System.out.println("New value of data:");
                printDebugData();
            }
            buildResourceAcls();
        }

        private void printDebugData() {
            int numRows = getRowCount();
            int numCols = getColumnCount();

            for (int i=0; i < numRows; i++) {
                System.out.print("    row " + i + ":");
                for (int j=0; j < numCols; j++) {
                    System.out.print("  " + data[i][j]);
                }
                System.out.println();
            }
            System.out.println("--------------------------");
        }
        
        // returns the objects in a specific row of the table model
        // that will be a String [principal], i, r, w, c, d values
        //
        private java.util.List<Object> getRow(int rowNum) {
            java.util.List<Object> list = new ArrayList<Object>();
            for (int i = 0; i < getColumnCount(); i++) {
                Object o = data[rowNum][i];
                list.add(o.toString());
            }
            return list;
        }
    }
   
    // tree model listener to detect changes in tree node (protected-resource) names
    // to make sure the resourceAclList objects associated with the node being
    // edited is changed to match the new node name
    //
    private class ResourceTreeModelListener implements TreeModelListener {
        public void treeNodesChanged(TreeModelEvent e) {

            DefaultMutableTreeNode node = (DefaultMutableTreeNode)tree.getLastSelectedPathComponent();

            if (node.isRoot()) {
                return;
            }
            
            // If the event lists children, then the changed
            // node is the child of the node we've already
            // gotten.  Otherwise, the changed node and the
            // specified node are the same.
            //
            currentResAcl.renameTo(node.toString());
            node.setUserObject(currentResAcl);
            ResourceAclList resList = (ResourceAclList)node.getUserObject();
            String newNodeName = node.toString();
            resList.renameTo(newNodeName);
        }
        
        public void treeNodesInserted(TreeModelEvent e) {
        }
        public void treeNodesRemoved(TreeModelEvent e) {
        }
        public void treeStructureChanged(TreeModelEvent e) {
        }
    }
    
    // creates a new policy store on disk
    //
    private class CreateAction extends AbstractAction {

		private static final long serialVersionUID = 7748875904554640642L;

		public void actionPerformed(ActionEvent e) {

            if (top != null) {
                // warn the user that they will overwrite what they have just created
                // with an OK/Cancel OptionDialogue
                // 
                Object[] options = {"Continue","Cancel"};
                int n = JOptionPane.showOptionDialog(null,
                            "Creating a new store will lose unsaved data!",
                            "Warning",
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.QUESTION_MESSAGE,
                            null,
                            options,
                            options[1]);
                System.out.println("value: " + n);
                if (n == 1)
                    return;
            }
            
            // prompt user for a place to write the new file
            //
            int retVal = fc.showSaveDialog(PermsNavigator.this);
            if (retVal == JFileChooser.APPROVE_OPTION) {
                File file = fc.getSelectedFile();

                try {
                    // create an empty document with default root nodes, write to disk then 
                    // load it back up
                    //
                    JTreeXMLTransformer transformer = new JTreeXMLTransformer(file, new DefaultMutableTreeNode("Default Application"));
                    @SuppressWarnings("unused")
					Document document = transformer.initDocument();
                    transformer.saveToFile();
                    createNodes(file);
                } catch (Exception e1) {
                    e1.printStackTrace();
                    JOptionPane.showMessageDialog(null, e1.getStackTrace(), "Error Creating New File", JOptionPane.ERROR_MESSAGE);
                }
                
            } else {
               JOptionPane.showMessageDialog(null, "No filename specified.", "Warning", JOptionPane.INFORMATION_MESSAGE);
               return;
            }
        }
    }
    
    // Action to handle saving the TreeModel out to XML
    //
    private class SaveAction extends AbstractAction {

		private static final long serialVersionUID = -8470543469088428756L;

		public void actionPerformed(ActionEvent e) {
             try {
                // prompt user for a place to write the new file
                //
                int retVal = fc.showSaveDialog(PermsNavigator.this);
                if (retVal == JFileChooser.APPROVE_OPTION) {
                    File file = fc.getSelectedFile();
                    int res = new JTreeXMLTransformer(file, top).saveToFile();
                    if (res == 1) {
                        JOptionPane.showMessageDialog(null, ("Policy store saved to: " + file), 
                                "Saved OK", JOptionPane.INFORMATION_MESSAGE);
                    }
                } else {
                   JOptionPane.showMessageDialog(null, "No filename specified.", "Warning", JOptionPane.INFORMATION_MESSAGE);
                   return;
                }
             } catch (Exception e1) {
                 e1.printStackTrace();
                 JOptionPane.showMessageDialog(null, e1.getStackTrace(), "Error Saving File", JOptionPane.ERROR_MESSAGE);
             }
         }
    } 
    
    // Action to handle loading XML policy store files
    //
    private class LoadAction extends AbstractAction {

		private static final long serialVersionUID = -4803138092725179325L;

		public void actionPerformed(ActionEvent e) {
            int retVal = fc.showOpenDialog(PermsNavigator.this);
            if (retVal == JFileChooser.APPROVE_OPTION) {
                File file = fc.getSelectedFile();
                clearPermissions();
                createNodes(file);
            }
        }
    }
    
 
     /**
      * Starts up the application
      */
     public static void main(String[] args) {
         @SuppressWarnings("unused")
		PermsNavigator pm = new PermsNavigator();
     }
    
 }