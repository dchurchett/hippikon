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
package com.hippikon.security.crypto;
 
 import java.io.*;
 import java.net.*;
 import java.util.*;
 import java.security.*;
 import java.security.spec.*;
 import javax.crypto.*;
 import javax.crypto.spec.*;
 
 /** 
  * DESSecretKeyGenerator is a command line driven utility class that 
  * generates a SecretKey using DES strong encryption and persists 
  * in a key file specified as a command line argument. The secret 
  * key may then be used encrypt and decrypt data for applications.<p>
  * 
  * If the key is compromised, a new key must be generated. Some
  * manual invervention may be required in order to prevent existing
  * encrypted data from being unavailable.<p>
  *
  * To use this class you will need to setup and install an encryption
  * DES provider, which can be downloaded from 
  * <a href="http://java.sun.com/products/jce/index-14.html">Sun JCE Page</a>.<p>
  *
  * <b>Examples</b><p>
  *
  * To create a new key locked with password 'my-password' in a file named
  * 'mykey.ser' issue the following command at a shell prompt:<p>
  *
  * <pre>
  * java com.hippikon.security.crypto.DESSecretKeyGenerator mykey.ser 'my-password'
  * </pre>
  *
  * To create a key in application code:<p>
  *
  * <pre>
  * DESSecretKeyGenerator keygen = new DESSecretKeyGenerator();
  * SecretKey key1 = keygen.generateKey("my-password");
  * SecretKey key2 = keygen.generateKey("my-other-password");
  * </pre>
  *
  * @author Dale Churchett
  * @version $Id: DESSecretKeyGenerator.java,v 1.1.1.1 2005/05/24 01:27:28 dalehippikon Exp $ 
  * @since JDK 1.2.2
  *
  */ 
 
 public class DESSecretKeyGenerator {
 
     private static final String ALGORITHM = "DES/CBC/PKCS5Padding";
     private SecretKey desKey;
     private String filename;
     private String password;
 
     /**
      * Creates a new DESSecretKeyGenerator object using a specified password
      * and filename to store the key as a seralized object.<p>
      *
      * @param filename the file where the generated SecretKey will be stored
      * using Serialization
      * @param password a String to use as the salt for the key generation. If 
      * NULL or a blank string, a default password will be used that is >38
      * characters in length.<p>
      *
      *
      * @exception Exception thrown if the DESSecretKeyGenerator could not
      * be initialized
      */
     public DESSecretKeyGenerator(String filename, String password)
     throws Exception {
 
         this.filename = filename;
         this.password = password;
 
         // this is dangerous practice and should be avoided
         // if we have to provide a default, a random key should
         // be generated internally and made available to the client
         //
         if (password == null)
             // e.g. password = generateRandomSecurePassword();
             password =  "!h0x<G28sa.*%?aslkWEKJso123lk23j52l3k";
 
         this.desKey = generateKey(password);
 
         ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(filename));
         out.writeObject(desKey);
     }
 
 
     /**
      * Creates a new DESSecretKeyGenerator that will use the default password   
      * and seralize the SecretKey to the specified filename.
      *
      * @param filename the file where the generated SecretKey will be stored
      * using Serialization
      *
      * @exception Exception thrown if the DESSecretKeyGenerator could not
      * be initialized
      */
     public DESSecretKeyGenerator(String filename)
     throws Exception {
         this(filename, null);
     }
 
     /**
      * Creates a new DESSecretKeyGenerator that uses the default password.
      * The key will not be stored as a serialized object.
      *
      * @exception IllegalArgumentException thrown if the password is NULL
      * or < 8 characters
      */
     public DESSecretKeyGenerator()
     throws IllegalArgumentException {
         this.password = null;
     }
 
 
     /**
      * Generates a SecretKey using a password provided. This 
      * method is provided for convenience should a client wish to quickly create
      * a transient SecretKey. If the two argument constructor was called, this
      * method will not replace the SecretKey already generated and seralized
      * to the specified filename.<p>
      *
      * The intended use of this method is:<p>
      *
      * <pre>
      * DESSecretKeyGenerator keygen = new DESSecretKeyGenerator();
      * SecretKey key = keygen.generateKey("my-bad-password");
      * // do something with the key
      * </pre>
      *
      * @param password a String used to generate the SecretKey
      *
      * @return a SecretKey object generated using the password provided 
      * in the object constructor
      *
      * @exception InvalidKeyException thrown if the key could not be generated
      * @exception NoSuchAlgorithmException thrown if the encryption algorithm could not be loaded
      * @exception InvalidKeySpecException thrown if the encryption algorithm is not available
      *
      */
     public SecretKey generateKey(String password)
     throws InvalidKeyException, NoSuchAlgorithmException,
     InvalidKeySpecException {
 
         byte[] desKeyData = password.getBytes();
         DESKeySpec desKeySpec = new DESKeySpec(desKeyData);
         SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
         desKey = keyFactory.generateSecret(desKeySpec);
 
         return desKey;
     }
 
     /**
      * Creates a KeySpec from a given SecretKey.
      * @param key the SecretKey object to translate to bytes
      * @return the DES key material in a byte array 
      */
     public byte[] makeBytesFromDESKey(SecretKey key) throws NoSuchAlgorithmException, InvalidKeySpecException {
     
         SecretKeyFactory desFactory = SecretKeyFactory.getInstance("DES");
         DESKeySpec spec = (DESKeySpec)desFactory.getKeySpec(key, DESKeySpec.class);
         return spec.getKey();
     }
 
     /**
      * This method translates a KeySpec into a SecretKey.
      * @param input a byte array of DES key data
      * @param offset the offset in key, where the DES key material starts 
      */
     public static SecretKey makeDESKey(byte[] input, int offset) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
         SecretKeyFactory desFactory = SecretKeyFactory.getInstance("DES");
         KeySpec spec = new DESKeySpec(input, offset);
         return desFactory.generateSecret(spec);
     }
     
     /**
      * Creates a new SecretKey using a specified filename and optional password. If
      * a password is provided it is safest to quote the password string.
      *
      * <b>Usage</b><p>
      *
      * <pre>
      * java com.hippikon.security.crypto.DESSecretKeyGenerator &lt;filename> [password]
      * </pre><p>
      *
      * To view a Help menu, pass in the '-h' option as the first command line argument
      *
      */
     public static void main(String[] args) throws Exception {
 
         if ((args.length == 1 && args[0] == "-h") || args.length < 1) {
             System.out.println("Usage: java DESSecretKeyGenerator <filename> [password]");
             System.exit(0);
         }
 
         if (args.length < 2)
             new DESSecretKeyGenerator(args[0]);
         else
             new DESSecretKeyGenerator(args[0], args[1]);
     
     }
 
 } // end class GenerateSSKey
 

