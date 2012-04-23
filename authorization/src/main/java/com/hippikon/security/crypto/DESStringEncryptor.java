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
 import org.apache.log4j.*;
 import com.hippikon.io.*;
 
 /**
  * This class provides convenient String DES/CBC encryption/decryption 
  * operations using JCE extensions. The current implementation provides
  * a reference for future development on the Security API. Only one
  * SecretKey is used whereas the class should support the ability to
  * use different keys without redeployment.<p>
  *
  * <b>Context Dependencies</b><p> 
  *
  * To use this class a JCE DES provider must be installed on the system. 
  * This class was developed using the Sun Reference JCE provider. Please
  * read the JCE documentation for JCE installation instructions and
  * configuration. Other providers may be used as per the JCE specification 
  * (Cryptix being the most likely candidate).
  *
  * @author Dale Churchett
  * @version $Id: DESStringEncryptor.java,v 1.1.1.1 2005/05/24 01:27:28 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 public class DESStringEncryptor {
 
     private static final String ALGORITHM = "DES/CBC/PKCS5Padding";
     private static final Logger log = Logger.getLogger("com.hippikon.security.crypto.DESStringEncryptor");
 
     private SecretKey desKey;
     private String keyFilename;
 
 
     // creates an encryptor with a filename that points to the
     // DES key to use
     //
     private DESStringEncryptor(String keyFilename)
     throws Exception {
         this.keyFilename = keyFilename;
         this.desKey = getSecretKey();
     }
 
     // defaults to the key.ser file that must live on the classpath
     //
     private DESStringEncryptor()
     throws Exception  {
         this("key.ser");
     }
 
     // points to the SecretKey instance to use for encryption/decryption
     //
     private DESStringEncryptor(SecretKey desKey) {
     	this.desKey = desKey;
     }
 
 
     /**
      * Returns a DESStringEncryptor object to use for DES encryption/decryption.
      * This method will attempt to use a file named key.ser located on the system
      * classpath
      *
      * @return a DESStringEncryptor object
      *
      * @exception Exception thrown if the object couldn not be instantiated
      */
     public static synchronized DESStringEncryptor getInstance()
     throws Exception  {
         return new DESStringEncryptor();
     }
 
     /**
      * Returns a DESStringEncryptor object that obtains a SecretKey generated
      * by the {@link DESSecretKeyGenerator} utility class and written to a file. The file
      * must be located in the system classpath if the filename is not an 
      * absolute path.
      *
      * @param keyFilename a file that stores a SecretKey created by the 
      * {@link DESSecretKeyGenerator} class
      *
      * @exception Exception thrown if the object couldn not be instantiated
      */
     public static synchronized DESStringEncryptor getInstance(String keyFilename)
     throws Exception  {
         return new DESStringEncryptor(keyFilename);
     }
 
     /**
      * Returns a DESStringEncryptor object that initializes a SecretKey.
      * @param desKey the SecretKey that will intialize this instance.
      * @exception Exception thrown if the object couldn not be instantiated
      */
     public static synchronized DESStringEncryptor getInstance(SecretKey desKey)
     throws Exception  {
         return new DESStringEncryptor(desKey);
     } 
      
 
     /**
      * Returns a SecretKey object stored in a file
      */
     private SecretKey getSecretKey() throws Exception { 
 
         FileInputStream fin = null;
         ObjectInputStream oin = null;
 
         try {
 
             File keyFile = FileUtil.findFileInClasspath(keyFilename);            
 
             fin = new FileInputStream(keyFile);
     	    oin = new ObjectInputStream(fin);
        	    desKey = (SecretKey)oin.readObject();
             return desKey;
 
         } finally {
 
             // make sure we close file descriptors - very important
             // in a server application
             //
             try {
                 if (fin != null) fin.close();
        	        if (oin != null) oin.close();
             } catch (Exception e) {
                 log.error(e.getMessage());
             }
         }
     }
 
     /**
      * Returns a decrypted byte array given an encrypted byte array.
      *
      * @param toDecrypt an encrypted byte array
      * @return a decrypted byte array
      * @exception Exception thrown if the decryption operation
      * could not be performed
      */
     public byte[] decrypt(byte[] toDecrypt) throws Exception {
 
 
         // read the init vector
         //
         int ivSize =toDecrypt[0];
         byte[] iv = new byte[ivSize];
 
         // do an array slice to get the Initialization Vector
         // we need this because we are using CBC
         //
         System.arraycopy(toDecrypt, 1, iv, 0, ivSize);
 
         IvParameterSpec ivps = new IvParameterSpec(iv);
 
         // use Data Encryption Standard
         //
         Cipher des = Cipher.getInstance(ALGORITHM);
         des.init(Cipher.DECRYPT_MODE, desKey, ivps);
 
         // calculate the number of bytes found at the start of the 
         // cipher text - this will be one byte plus the length of the IV
         //
         int ivBlock = iv.length + 1; 
         byte[] d = new byte[ toDecrypt.length - ivBlock ];
         System.arraycopy(toDecrypt, ivBlock, d, 0, d.length);
         byte[] output = des.doFinal(d);
 
         return output;
     }
 
     /**
      * Convenience method that encrypts a String and then Base64 encodes
      * to allow clients to handle as ASCII characters.
      *
      * @param toEncryptAndEncode the String to encrypt and base64 encode
      * @return an encrypted and base64 encoded String. This can be unencoded
      * and decrypted using the <code>base64Decrypt(String base64ToDecrypt)</code>
      * method.
      *
      * @exception Exception thrown if the encryption/encoding operation fails
      */
     public static String base64Encrypt(String toEncryptAndEncode) throws Exception {
         DESStringEncryptor enc = DESStringEncryptor.getInstance();
         byte[] encryptedString = enc.encrypt(toEncryptAndEncode);
         return Base64.encode(encryptedString);
     }
 
     /**
      * Convenience method that decrypts a String that is base64 encoded from
      * a byte array that was previously encrypted. Base64 encoding allows
      * the byte array to be handled as ASCII characters.
      *
      * @param base64ToDecrypt a Base64 encoded String
      * @return the decrypted String
      *
      * @exception Exception thrown if the decryption/unencoding operation fails
      */
     public static String base64Decrypt(String base64ToDecrypt) throws Exception {
         DESStringEncryptor enc = DESStringEncryptor.getInstance();
         byte[] notBase64String = Base64.decode(base64ToDecrypt);
         byte[] decryptedString = enc.decrypt(notBase64String);
         return new String(decryptedString);
     }
 
     /**
      * Returns an encrypted byte array of cipher text generated
      * from the String provided as the method parameter. 
      *
      * @param toEncrypt the String to encrypt
      *
      * @return a byte array containing the encrypted String
      *
      * @exception Exception thrown if the encryption operation
      * could not be performed
      */
     public byte[] encrypt(String toEncrypt) throws Exception {
 
         // use Data Encryption Standard 
         //
         Cipher des = Cipher.getInstance(ALGORITHM);
         des.init(Cipher.ENCRYPT_MODE, desKey);
 
         // write the init vector onto the output
         //
         byte[] iv = des.getIV();
         byte[] output = des.doFinal(toEncrypt.getBytes());
 
         // we calculate the size of the IV and add
         // the int as the first byte of the encrypted byte array
         // then we copy the IV itself and add the rest of the
         // cipher text
         //
         int ivBlock = iv.length + 1;
         byte[] toReturn = new byte[ ivBlock + output.length];
         toReturn[0] = (byte)iv.length;
 
         // now do some array slicing (would be nice if Java had the
         // same array slicing as Perl here, but you can't have everything)
         //
         System.arraycopy(iv, 0, toReturn, 1, iv.length);
         System.arraycopy(output, 0, toReturn, ivBlock, output.length);
     
         return toReturn;
 
     }
 
 
 
     /**
      * Used for testing only. This method takes a String and then
      * encrypts, Base64 encodes and URLEncodes into a format suitable
      * for storing in a cookie.<p>
      *
      * A SecretKey file may be passed in as the first command line argument,
      * else the default file will be used
      */
     public static void main(String[] args) {
 
         try {
             DESStringEncryptor enc = null;
 
             if (args.length < 1)
                 enc = DESStringEncryptor.getInstance();
             else
                 enc = DESStringEncryptor.getInstance(args[0]);
 
             String toEncrypt = "this is some content I'd like to encrypt";
             String toEncrypt2 = "asasdasdf asdasdfas asdfas";
 
             long startEn = new Date().getTime();
             
             byte[] encryptedString = enc.encrypt(toEncrypt);
             //System.out.println("Encrypted: " + new String(encryptedString));
             long stopEn = new Date().getTime();
             long timeEn = (stopEn - startEn);
 
             long startEn2 = new Date().getTime();
         
             byte[] encryptedString2 = enc.encrypt(toEncrypt2);
             String base64Str = Base64.encode(encryptedString2);
             System.out.println("Encrypted Base64: " + base64Str);
             String urlEncBase64Str = URLEncoder.encode(base64Str, "US-ASCII");
             System.out.println("URLEncoded: " + urlEncBase64Str);
 
             long stopEn2 = new Date().getTime();
             long timeEn2 = (stopEn2 - startEn2);
 
             String urlDecBase64Str = URLDecoder.decode(urlEncBase64Str, "US-ASCII");
             byte[] notBase64bytes = Base64.decode(urlDecBase64Str);
             byte[] decryptBase64 = enc.decrypt(notBase64bytes);
             System.out.println("Converted urlencoded, base64 converted, " + 
                                "DES encrypted string: " + new String(decryptBase64));
 
             long startDe = new Date().getTime();
             for (int i = 0; i < 100; i++) {
                 byte[] decryptedString = enc.decrypt(encryptedString);
                 //System.out.println("Decrypted: " + new String(decryptedString));
             }
             long stopDe = new Date().getTime();
             long timeDe = (stopDe - startDe);
 
             System.out.println("Encryption took: " + timeEn);
             System.out.println("Encryption took: " + timeEn2);
             System.out.println("Decryption took: " + timeDe / 100 + " ms per rev");
 
         } catch (Exception e) {
             e.printStackTrace();
         }
 
     }
             
 }

