package org.shaneking.codec;

import com.google.common.base.Strings;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.shaneking.skava.crypto.Cipher0;
import org.shaneking.skava.lang.SkavaException;
import org.shaneking.skava.lang.String0;
import org.shaneking.skava.security.Key0;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.util.UUID;

/**
 * named like codec or crypto (third party)
 * <p>
 * https://github.com/ShaneKing/sk-js/blob/mirror/src/Crypto0.js
 */
public class C3 {
  //ILoveYou
  public static final String DEFAULT_SALT = "494c6f7665596f75";
  private static final Cache<String, Cipher> SALT_DECRYPT_CACHE = CacheBuilder.newBuilder().maximumSize(13).build();
  private static final Cache<String, Cipher> SALT_ENCRYPT_CACHE = CacheBuilder.newBuilder().maximumSize(13).build();

  public static String aesDecrypt(String encrypted) throws Exception {
    return aesDecrypt(encrypted, DEFAULT_SALT);
  }

  public static String aesDecrypt(String encrypted, String salt) throws Exception {
    return new String(SALT_DECRYPT_CACHE.get(salt, () -> {
//      KeyGenerator.getInstance(Key0.AES).init(128);
      Cipher cipher = Cipher.getInstance(Cipher0.AES_ECB_PKCS5Padding);
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(salt.getBytes(), Key0.AES));
      return cipher;
    }).doFinal(Base64.decodeBase64(encrypted)));
  }

  public static String aesEncrypt(String content) throws Exception {
    return aesEncrypt(content, DEFAULT_SALT);
  }

  public static String aesEncrypt(String content, String salt) throws Exception {
    return Base64.encodeBase64String(SALT_ENCRYPT_CACHE.get(salt, () -> {
//      KeyGenerator.getInstance(Key0.AES).init(128);
      Cipher cipher = Cipher.getInstance(Cipher0.AES_ECB_PKCS5Padding);
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(salt.getBytes(), Key0.AES));
      return cipher;
    }).doFinal(content.getBytes(StandardCharsets.UTF_8)));
  }

  public static String genKey() {
    return genKey(UUID.randomUUID().toString().split(String0.MINUS)[0]);
  }

  public static String genKey(String eightLengthString) {
    if (Strings.isNullOrEmpty(eightLengthString) || eightLengthString.length() != 8) {
      throw new SkavaException(MessageFormat.format("Must 8 length string : {0}", String.valueOf(eightLengthString)));
    }
    return Hex.encodeHexString(eightLengthString.getBytes());
  }
}
