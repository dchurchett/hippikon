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
package com.hippikon.io;
 
 /**
  * Provides Base64 encoding/decoding routines as per RFC 1521.<p>
  *
  * @author Dale Churchett
  * @version $Id: Base64.java,v 1.1.1.1 2005/05/24 01:27:24 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 
 // this code was snagged from the O'Reilly Java Cryptography Book
 // examples - if we wanted an alternative, we could grab the 
 // com.sun.misc base64 class that was shipped with earlier versions
 // of the JDK
 
 public class Base64 {
 
 
     /**
      * Returns a base64 encoded String from a raw byte array
      *
      * @param raw a byte array to encode using base64
      * @return a base64 encoded String
      */
     public static String encode(byte[] raw) {
         StringBuffer encoded = new StringBuffer();
         for (int i = 0; i < raw.length; i += 3) {
             encoded.append(encodeBlock(raw, i));
         }
         return encoded.toString();
     }
 
 
     /**
      * Returns a base64 decoded byte array from a base64 encoded
      * string.
      *
      * @param base64 a base64 encoded String
      * @return a base64 decoded byte array
      */
     public static byte[] decode(String base64) {
         int pad = 0;
         for (int i = base64.length() - 1; base64.charAt(i) == '='; i--)
             pad++;
             int length = base64.length() * 6 / 8 - pad;
             byte[] raw = new byte[length];
             int rawIndex = 0;
             for (int i = 0; i < base64.length(); i += 4) {
                 int block = (getValue(base64.charAt(i)) << 18)
                     + (getValue(base64.charAt(i + 1)) << 12)
                     + (getValue(base64.charAt(i + 2)) << 6)
                     + (getValue(base64.charAt(i + 3)));
                 for (int j = 0; j < 3 && rawIndex + j < raw.length; j++)
                     raw[rawIndex + j] = (byte)((block >> (8 * (2 - j))) & 0xff);
                 rawIndex += 3;
                 }
         return raw;
     }
   
     private static char[] encodeBlock(byte[] raw, int offset) {
 
         int block = 0;
         int slack = raw.length - offset - 1;
         int end = (slack >= 2) ? 2 : slack;
         for (int i = 0; i <= end; i++)  {
             byte b = raw[offset + i];
             int neuter = (b < 0) ? b + 256 : b;
             block += neuter << (8 * (2 - i));
         }
         char[] base64 = new char[4];
         for (int i = 0; i < 4; i++) {
             int sixbit = (block >>> (6 * (3 - i))) & 0x3f;
             base64[i] = getChar(sixbit);
         }
         if (slack < 1) base64[2] = '=';
         if (slack < 2) base64[3] = '=';
 
         return base64;
     }
 
   
     private static char getChar(int sixBit) {
         if (sixBit >= 0 && sixBit <= 25)
             return (char)('A' + sixBit);
         if (sixBit >= 26 && sixBit <= 51)
             return (char)('a' + (sixBit - 26));
         if (sixBit >= 52 && sixBit <= 61)
             return (char)('0' + (sixBit - 52));
         if (sixBit == 62) return '+';
         if (sixBit == 63) return '/';
 
         return '?';
     }
 
   
   
     private static int getValue(char c) {
         if (c >= 'A' && c <= 'Z') return c - 'A';
         if (c >= 'a' && c <= 'z') return c - 'a' + 26;
         if (c >= '0' && c <= '9') return c - '0' + 52;
         if (c == '+') return 62;
         if (c == '/') return 63;
         if (c == '=') return 0;
         return -1;
     }
 
 }
 

