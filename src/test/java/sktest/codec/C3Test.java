package sktest.codec;

import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.shaneking.codec.C3;
import org.shaneking.skava.lang.String0;
import org.shaneking.skava.util.UUID0;
import org.shaneking.test.SKUnit;

import javax.crypto.BadPaddingException;
import java.util.UUID;

public class C3Test extends SKUnit {
  private String plainText = "plainText";
  private String cipherText = "urvlk7OI3tp6JUMD13lWTw==";

  @Test
  public void decrypt1() throws Exception {
    Assert.assertEquals(plainText, C3.aesDecrypt(cipherText));
  }

  @Test
  public void decrypt2() throws Exception {
    Assert.assertEquals(plainText, C3.aesDecrypt(cipherText, C3.DEFAULT_SALT));
  }

  @Test(expected = BadPaddingException.class)
  public void decrypt2Exception() throws Exception {
    Assert.assertNotEquals(plainText, C3.aesDecrypt(cipherText, C3.genKey()));
  }

  @Test
  public void encrypt1() throws Exception {
    Assert.assertEquals(cipherText, C3.aesEncrypt(plainText));
  }

  @Test
  public void encrypt2() throws Exception {
    Assert.assertEquals(cipherText, C3.aesEncrypt(plainText, C3.DEFAULT_SALT));
    Assert.assertNotEquals(cipherText, C3.aesEncrypt(plainText, C3.genKey()));
  }

  @Test
  public void genKey() throws Exception {
    Assert.assertEquals(16, C3.genKey().length());
  }

  @Test
  public void genKeyEightLength() throws Exception {
    tstPrint(C3.genKey(UUID.randomUUID().toString().split(String0.MINUS)[0]));
    Assert.assertEquals(8, UUID.randomUUID().toString().split(String0.MINUS)[0].length());
  }

  @Test(expected = Exception.class)
  public void genKeyEmpty() throws Exception {
    Assert.assertEquals(String0.EMPTY, C3.genKey(String0.EMPTY));
  }

  @Test(expected = Exception.class)
  public void genKeyNotEightLength() throws Exception {
    Assert.assertEquals(String0.EMPTY, C3.genKey(UUID0.l19()));
  }

  @Test(expected = Exception.class)
  public void genKeyNull() throws Exception {
    Assert.assertEquals(String0.EMPTY, C3.genKey(null));
  }

  @Test
  public void salt() {
    String salt = "ILoveYou";
    Assert.assertEquals(16, Hex.encodeHexString(salt.getBytes()).length());
    Assert.assertEquals(C3.DEFAULT_SALT, Hex.encodeHexString(salt.getBytes()));
  }
}
