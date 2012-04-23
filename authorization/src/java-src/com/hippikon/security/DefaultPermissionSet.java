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
 
 /**
  * The DefaultPermissionSet class provides a default implementation 
  * of the {@link PermissionSet} interface using bitwise operations to 
  * manipulate permission flags.<p>
  *
  * This class may be used by {@link Policy} implementations 
  * in order to create permissions defined within a {@link PolicyStore}.<p>
  *
  * A permission set is defined using one byte, with each bit representing
  * a permission flag:
  *
  * <blockquote>
  * <table border=1 cellspacing=3 width=300>
  * <tr>
  * <td align=center bgcolor="#aaeeff"><b>Bit</b></td>
  * <td align=center bgcolor="#aaeeff"><b>Name</b></td>
  * <td align=center bgcolor="#aaeeff"><b>Hex</b></td>
  * <td align=center bgcolor="#aaeeff"><b>Abbrev</b></td>
  * </tr>
  * <tr><td align=center>8</td><td align=center>Reserved</td><td align=center>0x00</td><td align=center>-</td></tr>
  * <tr><td align=center>7</td><td align=center>Reserved</td><td align=center>0x00</td><td align=center>-</td></tr>
  * <tr><td align=center>6</td><td align=center>Reserved</td><td align=center>0x00</td><td align=center>-</td></tr>
  * <tr><td align=center>5</td><td align=center>CREATE</td><td align=center>0x10</td><td align=center>i</td></tr>
  * <tr><td align=center>4</td><td align=center>READ</td><td align=center>0x08</td><td align=center>r</td></tr>
  * <tr><td align=center>3</td><td align=center>WRITE</td><td align=center>0x04</td><td align=center>w</td></tr>
  * <tr><td align=center>2</td><td align=center>CONTROL</td><td align=center>0x02</td><td align=center>c</td></tr>
  * <tr><td align=center>1</td><td align=center>DELETE</td><td align=center>0x01</td><td align=center>d</td></tr>
  * </table><p>
  * </blockquote>
  *
  * <b>Examples:</b><p>
  * 
  * <blockquote>
  * <table border=1 cellspacing=3 width=300>
  * <tr>
  * <td align=center bgcolor="#aaeeff"><b>Flags</b></td>
  * <td align=center bgcolor="#aaeeff"><b>Binary</b></td>
  * <td align=center bgcolor="#aaeeff"><b>Integer</b></td>
  * <td align=center bgcolor="#aaeeff"><b>Hex</b></td>
  * </tr>
  * <tr><td align=center>---i----</td><td>00010000</td><td align=center>16</td><td align=center>0x10</td></tr>
  * <tr><td align=center>---ir---</td><td>00011000</td><td align=center>24</td><td align=center>0x18</td></tr>
  * <tr><td align=center>---irwc-</td><td>00011110</td><td align=center>30</td><td align=center>0x1E</td></tr>
  * <tr><td align=center>----rwcd</td><td>00001111</td><td align=center>15</td><td align=center>0x0F</td></tr>
  * <tr><td align=center>----rwc-</td><td>00001110</td><td align=center>14</td><td align=center>0x0E</td></tr>
  * <tr><td align=center>----rw--</td><td>00001100</td><td align=center>12</td><td align=center>0x0C</td></tr>
  * <tr><td align=center>----r---</td><td>00001000</td><td align=center>8</td><td align=center>0x08</td></tr>
  * <tr><td align=center>-----w--</td><td>00000100</td><td align=center>4</td><td align=center>0x04</td></tr>
  * <tr><td align=center>------c-</td><td>0000010</td><td align=center>2</td><td align=center>0x02</td></tr>
  * <tr><td align=center>-------d</td><td>00000001</td><td align=center>1</td><td align=center>0x01</td></tr>
  * <tr><td align=center>--------</td><td>00000000</td><td align=center>0</td><td align=center>0x00</td></tr>
  * </table><p>
  * </blockquote>
  *
  * Note there are no mutator methods that allow application logic to alter 
  * permissions obtained from a PolicyStore. This ability is restricted
  * to Policy implementations via the MutablePermissionSet class, instances
  * of which may be obtained from the Policy superclass only.<p>
  *
  * The class also defines a mechanism of combining multiple PermissionSet
  * objects that performs a logical OR operation to find the complete
  * set of permissions of a single user accessing a ProtectedResource 
  * within an {@link AuthorizationContext}. The user may play multiple roles 
  * or have some special association with the ProtectedResource 
  * (such as the instance creator).<p>
  *
  * @author Dale Churchett
  * @version $Id: DefaultPermissionSet.java,v 1.3 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 public class DefaultPermissionSet implements PermissionSet {
 
	private static final long serialVersionUID = 4285864059232807374L;

	/**
      * An integer used to implement a binary bitset
      */
     protected int flags;
 
     static final int CREATE_FLAG  = (1 << 4);
     static final int READ_FLAG    = (1 << 3);
     static final int WRITE_FLAG   = (1 << 2);
     static final int CONTROL_FLAG = (1 << 1);
     static final int DELETE_FLAG  = (1 << 0);
 
     /**
      * Creates a new DefaultPermissionSet with initial
      * int value
      *
      * @param flags an int value representing the binary
      * set of permission flags
      */
     protected DefaultPermissionSet(int flags) {
         this.flags = flags;
     }
 
     /**
      * Creates a new DefaultPermissionSet from a string representation
      * of the ACL. See <code>getIntVal(String aclString)</code> and
      * the header documentation for the string format.
      *
      * @param aclString a String representation of the permission set
      * @exception IllegalArgumentException thrown if the string passed into the 
      * constructor is < 5 chars in length
      */
     protected DefaultPermissionSet(String aclString) throws IllegalArgumentException {
         this.flags = getIntVal(aclString);
     }
 
     /**
      * Creates a new DefaultPermissionSet object with values
      * based on another PermissionSet object. Based on the 
      * return values of the canXXX() methods, each flag in the 
      * bitset will be enabled or disabled accordingly. This 
      * effectively creates a deep-copy of a PermissionSet.
      *
      * @param perms a PermissionSet object
      *
      * @exception IllegalArgumentException thrown if the permissions set coming into the
      * method is null.
      */
     protected DefaultPermissionSet(PermissionSet perms) throws IllegalArgumentException {
         this.flags = 0;
         flags |= getIntPermissionSetValue(perms);
     }
 
 
     /**
      * Returns an integer value for a PermissionSet
      *
      * @param perms a PermissionSet object
      * @return an integer representation of the PermissionSet passed
      * in as a method argument
      */
     private int getIntPermissionSetValue(PermissionSet perms) throws IllegalArgumentException {
 
         if (perms == null)
             throw new IllegalArgumentException("NULL permissions being converted to int value");
 
         int flags = 0;
 
         if (perms.canCreate())
             flags |= CREATE_FLAG;
         if (perms.canRead())
             flags |= READ_FLAG;
         if (perms.canWrite())
             flags |= WRITE_FLAG;
         if (perms.canControl())
             flags |= CONTROL_FLAG;
         if (perms.canDelete())
             flags |= DELETE_FLAG;
 
         return flags;
     }
 
 
     /**
      * Creates a new DefaultPermissionSet with no
      * flags enabled.
      */
     public DefaultPermissionSet() {
         this.flags = 0;
     }
 
     public boolean canRead() {
         int p = flags & READ_FLAG;
         return (p == READ_FLAG) ? true : false;
     }
 
     public boolean canWrite() {
         int p = flags & WRITE_FLAG;
         return (p == WRITE_FLAG) ? true : false;
     }
 
     public boolean canControl() {
         int p = flags & CONTROL_FLAG;
         return (p == CONTROL_FLAG) ? true : false;
     }
 
     public boolean canDelete() {
         int p = flags & DELETE_FLAG;
         return (p == DELETE_FLAG) ? true : false;
     }
 
     public boolean canCreate() {
         int p = flags & CREATE_FLAG;
         return (p == CREATE_FLAG) ? true : false;
     }
     
     public boolean getCanCreate() {
    	 return canCreate();
     }
     
     public boolean getCanRead() {
    	 return canRead();
     }
     
     public boolean getCanWrite() {
    	 return canWrite();
     }
     
     public boolean getCanControl() {
    	 return canControl();
     }
     
     public boolean getCanDelete() {
    	 return canDelete();
     }
 
     /**
      * Adds a PermissionSet to affect the state of the PermissionSet
      * instance using an OR rule. This method should be used
      * to strengthen a PermissionSet with another PermissionSet.<p>
      *
      * For example, if a PermissionSet instance had only the READ flag
      * set, and a READ/WRITE PermissionSet was passed into this method, the
      * PermissionSet instance would be set to READ/WRITE.
      *
      * @post x |= y
      */
     public void addPermissions(PermissionSet perms) throws IllegalArgumentException {
         this.flags |= getIntPermissionSetValue(perms);
     }
 
     /**
      * Returns a Unix style string representation of the PermissionSet
      * using the following abbreviations:<p>
      *
      * i = canCreate() returns true<br>
      * r = canRead() returns true<br>
      * w = canWrite() returns true<br>
      * c = canControl() returns true<br>
      * d = canDelete() returns true<br>
      * - = canXXX() returns false<p>
      *
      * For example, a permission of read and write would be represented
      * by the String "-rw--"<p>
      *
      * @returns a String object 5 characters in length
      */
     public String toString() {
         StringBuffer sb = new StringBuffer();
         if (canCreate()) sb.append("i"); else sb.append("-");
         if (canRead()) sb.append("r"); else sb.append("-");
         if (canWrite()) sb.append("w"); else sb.append("-");
         if (canControl()) sb.append("c"); else sb.append("-");
         if (canDelete()) sb.append("d"); else sb.append("-");
         return sb.toString();
     }
 
 
     /**
      * Given a string representation of a set of permission flags, returns the 
      * integer value. The acl string value must be 5 characters in length and
      * use the irwcd format for CREATE, READ, WRITE, CONTROL and DELETE flags.
      *
      * @param acl a String representation of an access control list entry
      * @return the int value representing the String acl passed in
      *
      * @exception IllegalArgumentException thrown if the string representation is < 5 chars in length
      */
     protected static int getIntVal(String acl) throws IllegalArgumentException {
 
         if (acl == null || acl.length() < 5)
             return 0;
 
         char[] c = acl.toCharArray();
         if (c.length < 5) {
             throw new IllegalArgumentException("Illegal string representation: >>>" + acl + "<<<");
         }
 
         int flags = 0;
 
         if (c[0] == 'i') flags |= DefaultPermissionSet.CREATE_FLAG;
         if (c[1] == 'r') flags |= DefaultPermissionSet.READ_FLAG;
         if (c[2] == 'w') flags |= DefaultPermissionSet.WRITE_FLAG;
         if (c[3] == 'c') flags |= DefaultPermissionSet.CONTROL_FLAG;
         if (c[4] == 'd') flags |= DefaultPermissionSet.DELETE_FLAG;
     
         return flags;
     }
     
     protected int getIntValue() {
         return getIntVal(toString());
     }
 
 }

