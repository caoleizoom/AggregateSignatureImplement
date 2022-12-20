package ref13;


import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.python.antlr.ast.Str;

import java.io.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;



public class ref13{
    //------------------------------------系统初始化--------------------------------
    public static void setup(String pairingFile, String publicFile,String mskFile) {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //设置KGC主私钥s
        Element a = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();
        mskProp.setProperty("a", Base64.getEncoder().encodeToString(a.toBytes()));
        storePropToFile(mskProp, mskFile);

        //设置主公钥K_pub,T_pub和公开参数
        Element P = bp.getG1().newRandomElement().getImmutable();
        Element K_pub = P.powZn(a).getImmutable();
        Properties pubProp = new Properties();
        pubProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pubProp.setProperty("K_pub", Base64.getEncoder().encodeToString(K_pub.toBytes()));
        storePropToFile(pubProp, publicFile);
    }

    public  static  void pseudo(String pairingFile,String rid, String pidFile ) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        byte[] rid_hash = sha1(rid);
        Element pid = bp.getZr().newElementFromHash(rid_hash,0,rid_hash.length);
        Properties pidProp = new Properties();
        pidProp.setProperty("pid", Base64.getEncoder().encodeToString(pid.toBytes()));
        storePropToFile(pidProp,pidFile);
    }


    //---------------------------注册阶段-----------------------------------
    public static void keygen(String pairingFile, String publicFile, String mskFile, String pidFile,String pkFile ,String skFile) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //公共参数群G生成元P,和主公钥Pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String K_pubStr = pubProp.getProperty("K_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element K_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(K_pubStr)).getImmutable();

        //用户的操作：
        Element vsk = bp.getZr().newRandomElement().getImmutable();
        Element vpk = P.powZn(vsk).getImmutable();

        //KGC的操作:
        //取出主私钥s
        Properties mskProp = loadPropFromFile(mskFile);
        String aStr = mskProp.getProperty("a");
        Element a = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(aStr)).getImmutable();
        //获取假名
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();

        //生成部分私钥
        byte[] h2_hash = sha1(pid.toString() + vpk.toString());
        Element Q = bp.getZr().newElementFromHash(h2_hash, 0, h2_hash.length).getImmutable();
        Element W = K_pub.powZn(Q).getImmutable();
        Element psk = a.mul(Q);

        //车辆的操作：
        //设置私钥
        Properties skProp = new Properties();
        skProp.setProperty("vsk", Base64.getEncoder().encodeToString(vsk.toBytes()));
        skProp.setProperty("psk", Base64.getEncoder().encodeToString(psk.toBytes()));

        //设置公钥
        Properties pkProp = new Properties();
        pkProp.setProperty("vpk", Base64.getEncoder().encodeToString(vpk.toBytes()));
        //存储公私钥
        storePropToFile(skProp, skFile);
        storePropToFile(pkProp, pkFile);
    }

    //--------------------------------IdentityAuthentication Phase------------------------------------------------
    public static void sign(String pairingFile, String publicFile, String pkFile, String skFile,  String pidFile, String message, String signFile, int index) throws NoSuchAlgorithmException, IOException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //取出公开参数P
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        Element P= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();

        //取出假名
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();

        //取出公钥
        Properties pkProp = loadPropFromFile(pkFile);
        String vpkStr = pkProp.getProperty("vpk");
        Element vpk= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(vpkStr)).getImmutable();

        //取出签名的私钥vsk，psk
        Properties skProp = loadPropFromFile(skFile);
        String vskStr = skProp.getProperty("vsk");
        String pskStr = skProp.getProperty("psk");
        Element vsk= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(vskStr)).getImmutable();
        Element psk= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(pskStr)).getImmutable();

        //计算签名
        Element r = bp.getZr().newRandomElement().getImmutable();
        Element U = P.powZn(r).getImmutable();
        byte[] h3_hash = sha1(message+pid.toString()+vpk.toString()+U.toString());
        Element hi = bp.getZr().newElementFromHash(h3_hash,0,h3_hash.length).getImmutable();
        Element S = psk.add(vsk.mul(hi)).getImmutable();

        //保存签名
        FileReader reader = new FileReader(signFile);
        Properties signSave = new Properties();
        signSave.load(reader);
        signSave.setProperty("U"+ index, Base64.getEncoder().encodeToString(U.toBytes()));
        signSave.setProperty("S"+ index, Base64.getEncoder().encodeToString(S.toBytes()));
        FileWriter writer = new FileWriter(signFile);
        signSave.store(writer, "新增信息");
        reader.close();
        writer.close();
    }


    public static void verify(String pairingFile, String publicFile ,String pidFile ,String pkFile, String message, String sigFile ) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //获取生成元P和主公钥P_pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String K_pubStr = pubProp.getProperty("K_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element K_pub= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(K_pubStr)).getImmutable();

        //获取假名
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();
        //获取公钥vpk
        Properties pkProp = loadPropFromFile(pkFile);
        String vpkStr = pkProp.getProperty("vpk");
        Element vpk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(vpkStr)).getImmutable();

        //获取签名
        Properties signProp = loadPropFromFile(sigFile);
        String UStr = signProp.getProperty("U"+1);
        String SStr = signProp.getProperty("S"+1);
        Element U = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(UStr)).getImmutable();
        Element S = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(SStr)).getImmutable();

        //验证签名
        byte[] h2_hash = sha1(pid.toString()+vpk.toString());
        Element Q = bp.getZr().newElementFromHash(h2_hash,0,h2_hash.length).getImmutable();
        byte[] h3_hash = sha1(message+pid.toString()+vpk.toString()+U.toString());
        Element hi = bp.getZr().newElementFromHash(h3_hash,0,h3_hash.length).getImmutable();

        if (P.powZn(S).isEqual(K_pub.powZn(Q).add(vpk.powZn(hi)))){
            System.out.println(message + "：" + "签名验证成功！");
        }else{
            System.out.println(message + "：" + "签名验证失败！");
        }
    }

    public static  void aggreGate(String pairingFile, String signFile, String aggSignFile)throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingFile);
        Properties sigProp = loadPropFromFile(signFile);
        //计算聚合签名
        Element aggS = bp.getZr().newZeroElement().getImmutable();
        for (int i = 0 ; i<sigProp.size()/2 ; i++){
            String SStr = sigProp.getProperty("S" + i);
            Element S = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(SStr)).getImmutable();
            aggS = aggS.add(S).getImmutable();
        }
        //保存聚合签名
        Properties saveAgg = new Properties();
        saveAgg.setProperty("aggS",Base64.getEncoder().encodeToString(aggS.toBytes()));
        storePropToFile(saveAgg,aggSignFile);
    }

    public static  void aggreGateVerify(String pairingFile, String publicFile, String pidFile, String pkFile, String aggSignFile, String signFile, String[] messages) throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //获取G1群生成元P和主公钥P_pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String K_pubStr = pubProp.getProperty("K_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element K_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(K_pubStr)).getImmutable();

        //获取用户假名
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();

        // 获取用户公钥
        Properties pkProp = loadPropFromFile(pkFile);
        String vpkStr = pkProp.getProperty("vpk");
        Element vpk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(vpkStr)).getImmutable();

        //获取聚合签名
        Properties aggProp = loadPropFromFile(aggSignFile);
        String aggSStr = aggProp.getProperty("aggS");
        Element aggS = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(aggSStr)).getImmutable();


        //验证聚合签名
        byte [] h2_hash = sha1(pid.toString()+vpk.toString());
        Element Q = bp.getZr().newElementFromHash(h2_hash,0,h2_hash.length);
        Properties sigProp = loadPropFromFile(signFile);
        Element W = bp.getG1().newZeroElement().getImmutable();
        Element hivpk = bp.getG1().newZeroElement().getImmutable();
        for (int i = 0 ;i<messages.length;i++){
            String UStr = sigProp.getProperty("U"+i);
            Element Ui = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(UStr)).getImmutable();
            byte[] h3_hash = sha1(messages[i]+pid.toString()+vpk.toString()+Ui.toString());
            Element hi = bp.getZr().newElementFromHash(h3_hash,0,h3_hash.length);
            W = W.add(K_pub.powZn(Q)).getImmutable();
            hivpk = hivpk.add(vpk.powZn(hi)).getImmutable();
        }
        if(P.powZn(aggS).isEqual(W.add(hivpk))){
            System.out.println("聚合签名验证成功！");
        }else {
            System.out.println("聚合签名验证失败！");
        }
    }

    public static void storePropToFile(Properties prop, String fileName){
        try(FileOutputStream out = new FileOutputStream(fileName)){
            prop.store(out, null);
        }
        catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (
                FileInputStream in = new FileInputStream(fileName)){
            prop.load(in);
        }
        catch (IOException e){
            e.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }

    public static byte[] sha1(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static void main(String[] args) throws Exception {
        String ridAlice = "AABBCCDDEEFFGGHH";
        String ID_Rj =  "rsuj@snnu.edu.com";
        String [] messages  =new String[] {"密码学","12345678","计算机","张无忌","计算机学院","密码学","12345678","计算机","张无忌","计算机学院","密码学","12345678","计算机","张无忌","计算机学院","密码学","12345678","计算机","张无忌","计算机学院"};
        String dir = "data_ref13/";
        String pairingParametersFileName = "data_ref13/a.properties";
        String publicParameterFileName = dir + "pub.properties";
        String pidFileName = dir + "pid.properties";
        String mskFileName = dir + "msk.properties";
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "sk.properties";
        String signFileName = dir + "sign.properties";
        String aggSignFileName = dir + "agg.properties";


        setup(pairingParametersFileName,publicParameterFileName,mskFileName);
        pseudo(pairingParametersFileName,ridAlice,pidFileName);
        keygen(pairingParametersFileName,publicParameterFileName,mskFileName,pidFileName,pkFileName,skFileName);
        System.out.println(messages.length);
        for(int i = 0 ; i<messages.length;i++){
            long start1 = System.currentTimeMillis();
            sign(pairingParametersFileName,publicParameterFileName,pkFileName,skFileName,pidFileName,messages[i],signFileName,i);
            long end1 = System.currentTimeMillis();
            System.out.print("签名时间为：");
            System.out.println(end1-start1);
        }
        for (int i = 0 ; i< 10;i++){
            long start2 = System.currentTimeMillis();
            verify(pairingParametersFileName,publicParameterFileName,pidFileName,pkFileName,messages[1],signFileName);
            long end2 = System.currentTimeMillis();
            System.out.print("验证时间为；");
            System.out.println(end2-start2);
        }
        aggreGate(pairingParametersFileName,signFileName,aggSignFileName);
        for (int i = 0 ; i< 10;i++){
            long start3 = System.currentTimeMillis();
            aggreGateVerify(pairingParametersFileName,publicParameterFileName,pidFileName,pkFileName,aggSignFileName,signFileName,messages);
            long end3 = System.currentTimeMillis();
            System.out.print("聚合验证时间为；");
            System.out.println(end3-start3);
        }
//        for (int i =0; i< 10;i++){
//            long start = System.currentTimeMillis();
//            boolean res = verify(pairingParametersFileName,publicParameterFileName,pidAlice,fuzzyFileName,pkFileName,messages[1],signFileName);
//            long end = System.currentTimeMillis();
//            System.out.println(end-start);
//        }

        //System.out.println(res);



    }

}

