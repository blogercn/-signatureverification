package com.aizuzi.verificationdemo;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import com.ushaqi.zhuishushenqi.signture;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import static com.ushaqi.zhuishushenqi.signture.httpConnect;
import static com.ushaqi.zhuishushenqi.signture.readFromAssets;

public class MainActivity extends AppCompatActivity {

  // Used to load the 'native-lib' library on application startup.
  /*
  static {
    System.loadLibrary("native-lib");
  }
*/
  protected TextView appSignaturesTv;
  protected TextView jniSignaturesTv;
  protected Button checkBtn;
  protected Button tokenBtn;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    super.setContentView(R.layout.activity_main);

    initView();

    appSignaturesTv.setText(getSha1Value(MainActivity.this) +"_________"+getMd5Value(this) +
    "==="+getApkMd5() +"---------"+getDexMd5()+"-----"+ signture.getMd5("abcdef")+"+++++"+getMd5Str(this, "abcdef"));
    jniSignaturesTv.setText(signture.getSignaturesSha1(MainActivity.this));

    readFromAssets(getAssets(),"log.txt"); //onCreate中添加调用
    httpConnect();
  }

  private View.OnClickListener clickListener = new View.OnClickListener(){
    @Override
    public void onClick(View v) {
      boolean result = signture.checkSha1(MainActivity.this);

      if(result){
        Toast.makeText(getApplicationContext(),"验证通过",Toast.LENGTH_LONG).show();
      }else{
        Toast.makeText(getApplicationContext(),"验证不通过，请检查valid.cpp文件配置的sha1值",Toast.LENGTH_LONG).show();
      }
    }
  };

  private View.OnClickListener tokenClickListener = new View.OnClickListener(){
    @Override
    public void onClick(View v) {
      String result = signture.getToken(MainActivity.this,"12345");

      Toast.makeText(getApplicationContext(),result,Toast.LENGTH_LONG).show();
    }
  };

  private void initView() {
    appSignaturesTv = (TextView) findViewById(R.id.app_signatures_tv);
    jniSignaturesTv = (TextView) findViewById(R.id.jni_signatures_tv);
    checkBtn = (Button) findViewById(R.id.check_btn);
    tokenBtn = (Button) findViewById(R.id.token_btn);

    checkBtn.setOnClickListener(clickListener);
    tokenBtn.setOnClickListener(tokenClickListener);
  }

  /**
   * A native method that is implemented by the 'native-lib' native library,
   * which is packaged with this application.
   */
  /*
  public native String getSignaturesSha1(Context context);
  public native boolean checkSha1(Context context);
  public native String getToken(Context context, String userId);
  public native String getMd5(String mdstr);
*/

  public String getSha1Value(Context context) {
    try {
      PackageInfo info = context.getPackageManager().getPackageInfo(
          context.getPackageName(), PackageManager.GET_SIGNATURES);
      byte[] cert = info.signatures[0].toByteArray();
      MessageDigest md = MessageDigest.getInstance("SHA1");
      byte[] publicKey = md.digest(cert);
      StringBuffer hexString = new StringBuffer();
      for (int i = 0; i < publicKey.length; i++) {
        String appendString = Integer.toHexString(0xFF & publicKey[i])
            .toUpperCase(Locale.US);
        if (appendString.length() == 1)
          hexString.append("0");
        hexString.append(appendString);
      }
      String result = hexString.toString();
      return result.substring(0, result.length());
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }
  public String getMd5Str(Context context, String str) {
    try {

      MessageDigest md = MessageDigest.getInstance("MD5");
      byte[] publicKey = md.digest(str.getBytes());
      StringBuffer hexString = new StringBuffer();
      for (int i = 0; i < publicKey.length; i++) {
        String appendString = Integer.toHexString(0xFF & publicKey[i])
                .toUpperCase(Locale.US);
        if (appendString.length() == 1)
          hexString.append("0");
        hexString.append(appendString);
      }
      String result = hexString.toString();
      return result.substring(0, result.length());
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }
  public String getMd5Value(Context context) {
    try {
      PackageInfo info = context.getPackageManager().getPackageInfo(
              context.getPackageName(), PackageManager.GET_SIGNATURES);
      byte[] cert = info.signatures[0].toByteArray();
      MessageDigest md = MessageDigest.getInstance("MD5");
      byte[] publicKey = md.digest(cert);
      StringBuffer hexString = new StringBuffer();
      for (int i = 0; i < publicKey.length; i++) {
        String appendString = Integer.toHexString(0xFF & publicKey[i])
                .toUpperCase(Locale.US);
        if (appendString.length() == 1)
          hexString.append("0");
        hexString.append(appendString);
      }
      String result = hexString.toString();
      return result.substring(0, result.length());
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }
  /**
   * 校验Dex CRC值
   */
  private long getDexCrc() {
    String apkPath = this.getPackageCodePath();
    try {
      ZipFile zipFile = new ZipFile(apkPath);
      ZipEntry dexEntry = zipFile.getEntry("classes.dex");

      //计算classes.dex的 crc
      long dexEntryCrc = dexEntry.getCrc();
      Log.d("DEX", dexEntryCrc + "");
      return dexEntryCrc;
    } catch (IOException e) {
      e.printStackTrace();
    }
    return -1;
  }

  /**
   * 校验APK MD5值
   */
  private String getApkMd5() {
    //获取data/app/****/base.apk 路径
    String apkPath = getPackageResourcePath();
    Log.d("APK", apkPath);
    MessageDigest msgDigest;
    try {
      //获取apk并计算MD5值
      msgDigest = MessageDigest.getInstance("MD5");
      byte[] bytes = new byte[4096];
      int count;
      FileInputStream fis;
      fis = new FileInputStream(new File(apkPath));

      while ((count = fis.read(bytes)) > 0) {
        msgDigest.update(bytes, 0, count);
      }
      //计算出MD5值
      BigInteger bInt = new BigInteger(1, msgDigest.digest());
      String md5 = bInt.toString(16);
      fis.close();
      Log.d("APK", md5);
      return md5;
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
    return null;
  }
  private String getDexMd5() {
    String apkPath = this.getPackageCodePath();
    Log.d("APK", apkPath);

    MessageDigest msgDigest;
    try {
      ZipFile zipFile = new ZipFile(apkPath) ;
      ZipInputStream zipInput = new ZipInputStream(new FileInputStream(apkPath)) ;
      ZipEntry dexEntry = null;
      while((dexEntry = zipInput.getNextEntry())!=null){	// 得到一个压缩实体
        if (dexEntry.getName().indexOf("classes.dex") != -1){
          break;
        }
      }
      zipInput.close() ;
      //获取apk并计算MD5值
      msgDigest = MessageDigest.getInstance("MD5");
      byte[] bytes = new byte[4096];
      int count;
      InputStream fis;
      fis = zipFile.getInputStream(dexEntry);

      while ((count = fis.read(bytes)) > 0) {
        msgDigest.update(bytes, 0, count);
      }
      //计算出MD5值
      BigInteger bInt = new BigInteger(1, msgDigest.digest());
      String md5 = bInt.toString(16);
      fis.close();
      Log.d("APK", md5);
      return md5;
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
    return null;
  }


  public static String byte2hex(byte[] b) {
    String hs = "";
    String stmp = "";
    for (int n = 0; n < b.length; n++) {
      stmp = (java.lang.Integer.toHexString(b[n] & 0XFF));
      if (stmp.length() == 1) {
        hs = hs + "0" + stmp;
      } else {
        hs = hs + stmp;
      }
    }
    return hs;
  }
  //读取本地JSON字符
  public static String ReadDayDayString(Context context) {
    InputStream is = null;
    String msg = null;
    try {
      is = context.getResources().getAssets().open("mprespons.txt");
      byte[] bytes = new byte[is.available()];
      is.read(bytes);
      msg = new String(bytes);
    } catch (IOException e) {
      e.printStackTrace();
    } finally {
      try {
        is.close();
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
    return msg;
  }

  }
