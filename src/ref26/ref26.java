package ref26;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.io.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;

public class ref26{
    //------------------------------------系统初始化--------------------------------
    public static void setup(String pairingFile, String publicFile,String mskFile) {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //设置KGC主私钥s
        Element s = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();
        mskProp.setProperty("s", Base64.getEncoder().encodeToString(s.toBytes()));
        storePropToFile(mskProp, mskFile);

        //设置主公钥K_pub和公开参数
        Element P = bp.getG1().newRandomElement().getImmutable();
        Element Q = bp.getG1().newRandomElement().getImmutable();
        Element P_pub = P.powZn(s).getImmutable();
        Properties pubProp = new Properties();
        pubProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pubProp.setProperty("Q", Base64.getEncoder().encodeToString(Q.toBytes()));
        pubProp.setProperty("P_pub", Base64.getEncoder().encodeToString(P_pub.toBytes()));
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
        //公共参数群G生成元P,和主公钥P_pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();

        //KGC的操作:
        //取出主私钥s
        Properties mskProp = loadPropFromFile(mskFile);
        String sStr = mskProp.getProperty("s");
        Element s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sStr)).getImmutable();
        //获取假名
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();

        //生成部分私钥
        Element r = bp.getZr().newRandomElement().getImmutable();
        Element R = P.powZn(r).getImmutable();
        byte[] h2_hash = sha1(pid.toString() + R.toString());
        Element k = bp.getZr().newElementFromHash(h2_hash, 0, h2_hash.length).getImmutable();
        Element d = r.add(k.mul(s)).getImmutable();

        //车辆的操作：
        Element x = bp.getZr().newRandomElement().getImmutable();
        Element X = P.powZn(x).getImmutable();
        //设置私钥
        Properties skProp = new Properties();
        skProp.setProperty("x", Base64.getEncoder().encodeToString(x.toBytes()));
        skProp.setProperty("d", Base64.getEncoder().encodeToString(d.toBytes()));

        //设置公钥
        Properties pkProp = new Properties();
        pkProp.setProperty("X", Base64.getEncoder().encodeToString(X.toBytes()));
        pkProp.setProperty("R", Base64.getEncoder().encodeToString(R.toBytes()));
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
        String QStr = pubProp.getProperty("Q");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element Q = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QStr)).getImmutable();

        //取出假名
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();

        //取出公钥
        Properties pkProp = loadPropFromFile(pkFile);
        String XStr = pkProp.getProperty("X");
        String RStr = pkProp.getProperty("R");
        Element X= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XStr)).getImmutable();
        Element R= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();

        //取出签名的私钥x，d
        Properties skProp = loadPropFromFile(skFile);
        String xStr = skProp.getProperty("x");
        String dStr = skProp.getProperty("d");
        Element x= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xStr)).getImmutable();
        Element d= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(dStr)).getImmutable();

        //计算签名
        Element u = bp.getZr().newRandomElement().getImmutable();
        Element U = P.powZn(u).getImmutable();
        Element V = Q.powZn(u).getImmutable();
        byte[] h3_hash = sha1(message+pid.toString()+U.toString()+V.toString()+X.toString()+R.toString());
        Element hi = bp.getZr().newElementFromHash(h3_hash,0,h3_hash.length).getImmutable();
        Element W = Q.powZn(d.add(hi.mul(x))).add(V).getImmutable();

        //保存签名
        FileReader reader = new FileReader(signFile);
        Properties signSave = new Properties();
        signSave.load(reader);
        signSave.setProperty("U"+ index, Base64.getEncoder().encodeToString(U.toBytes()));
        signSave.setProperty("V"+ index, Base64.getEncoder().encodeToString(V.toBytes()));
        signSave.setProperty("W"+ index, Base64.getEncoder().encodeToString(W.toBytes()));
        FileWriter writer = new FileWriter(signFile);
        signSave.store(writer, "新增信息");
        reader.close();
        writer.close();
    }


    public static void verify(String pairingFile, String publicFile ,String pidFile ,String pkFile, String message, String sigFile ) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //获取生成元P,Q和主公钥P_pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String QStr = pubProp.getProperty("Q");
        String P_pubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element Q = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QStr)).getImmutable();
        Element P_pub= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubStr)).getImmutable();

        //获取假名
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();
        //获取公钥X,R
        Properties pkProp = loadPropFromFile(pkFile);
        String XStr = pkProp.getProperty("X");
        String RStr = pkProp.getProperty("R");
        Element X = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XStr)).getImmutable();
        Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();

        //获取签名
        Properties signProp = loadPropFromFile(sigFile);
        String UStr = signProp.getProperty("U"+1);
        String VStr = signProp.getProperty("V"+1);
        String WStr = signProp.getProperty("W"+1);
        Element U = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(UStr)).getImmutable();
        Element V = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(VStr)).getImmutable();
        Element W = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(WStr)).getImmutable();

        //验证签名
        byte[] h2_hash = sha1(pid.toString()+R.toString());
        Element k = bp.getZr().newElementFromHash(h2_hash,0,h2_hash.length).getImmutable();
        byte[] h3_hash = sha1(message+pid.toString()+U.toString()+V.toString()+X.toString()+R.toString());
        Element hi = bp.getZr().newElementFromHash(h3_hash,0,h3_hash.length).getImmutable();

        Element left = R.add(P_pub.powZn(k).add(X.powZn(hi).add(U))).getImmutable();
        if (bp.pairing(W,P).isEqual(bp.pairing(left,Q))){
            System.out.println(message + "：" + "签名验证成功！");
        }else{
            System.out.println(message + "：" + "签名验证失败！");
        }
    }

    public static  void aggreGate(String pairingFile, String signFile, String aggSignFile)throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingFile);
        Properties sigProp = loadPropFromFile(signFile);
        //计算聚合签名
        Element aggU = bp.getG1().newZeroElement().getImmutable();
        Element aggV = bp.getG1().newZeroElement().getImmutable();
        Element aggW = bp.getG1().newZeroElement().getImmutable();
        for (int i = 0 ; i<sigProp.size()/3 ; i++){
            String UStr = sigProp.getProperty("U" + i);
            String VStr = sigProp.getProperty("V" + i);
            String WStr = sigProp.getProperty("W" + i);
            Element U = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(UStr)).getImmutable();
            Element V = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(VStr)).getImmutable();
            Element W = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(WStr)).getImmutable();
            aggU = aggU.add(U).getImmutable();
            aggV = aggV.add(V).getImmutable();
            aggW = aggW.add(W).getImmutable();
        }
        //保存聚合签名
        Properties saveAgg = new Properties();
        saveAgg.setProperty("aggU",Base64.getEncoder().encodeToString(aggU.toBytes()));
        saveAgg.setProperty("aggV",Base64.getEncoder().encodeToString(aggV.toBytes()));
        saveAgg.setProperty("aggW",Base64.getEncoder().encodeToString(aggW.toBytes()));
        storePropToFile(saveAgg,aggSignFile);
    }

    public static  void aggreGateVerify(String pairingFile, String publicFile, String pidFile, String pkFile, String aggSignFile, String signFile, String[] messages) throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //获取G1群生成元P,Q和主公钥P_pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String QStr = pubProp.getProperty("Q");
        String P_pubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element Q = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubStr)).getImmutable();

        //获取用户假名
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();

        // 获取用户公钥
        Properties pkProp = loadPropFromFile(pkFile);
        String XStr = pkProp.getProperty("X");
        String RStr = pkProp.getProperty("R");
        Element X = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XStr)).getImmutable();
        Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();

        //获取聚合签名
        Properties aggProp = loadPropFromFile(aggSignFile);
        String aggUStr = aggProp.getProperty("aggU");
        String aggWStr = aggProp.getProperty("aggW");
        Element aggU = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(aggUStr)).getImmutable();
        Element aggW = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(aggWStr)).getImmutable();


        //验证聚合签名
        byte [] h2_hash = sha1(pid.toString()+R.toString());
        Element k = bp.getZr().newElementFromHash(h2_hash,0,h2_hash.length);
        Properties sigProp = loadPropFromFile(signFile);

        Element sum_R = bp.getG1().newZeroElement().getImmutable();
        Element sum_k_Ppub = bp.getG1().newZeroElement().getImmutable();
        Element sum_hi_X = bp.getG1().newZeroElement().getImmutable();
        for (int i = 0 ;i<messages.length;i++){
            String UStr = sigProp.getProperty("U" + i);
            String VStr = sigProp.getProperty("V" + i);
            String WStr = sigProp.getProperty("W" + i);
            Element U = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(UStr)).getImmutable();
            Element V = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(VStr)).getImmutable();
            Element W = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(WStr)).getImmutable();
            byte[] h3_hash = sha1(messages[i]+pid.toString()+U.toString()+V.toString()+X.toString()+R.toString());
            Element hi = bp.getZr().newElementFromHash(h3_hash,0,h3_hash.length);
            sum_R = sum_R.add(R).getImmutable();
            sum_k_Ppub = sum_k_Ppub.add(P_pub.powZn(k));
            sum_hi_X = sum_hi_X.add(X.powZn(hi));
        }
        if(bp.pairing(aggW,P).isEqual(bp.pairing(sum_R.add(sum_k_Ppub.add(sum_hi_X.add(aggU))),Q))){
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
        String dir = "data_ref26/";
        String pairingParametersFileName = "data_ref26/a.properties";
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
            System.out.print("签名的时间为：");
            System.out.println(end1-start1);
        }
        for (int i = 0; i< 10; i++){
            long start2 = System.currentTimeMillis();
            verify(pairingParametersFileName,publicParameterFileName,pidFileName,pkFileName,messages[1],signFileName);
            long end2 = System.currentTimeMillis();
            System.out.print("验证的时间为：");
            System.out.println(end2-start2);
        }
        aggreGate(pairingParametersFileName,signFileName,aggSignFileName);
        for (int i = 0; i< 10; i++){
            long start3 = System.currentTimeMillis();
            aggreGateVerify(pairingParametersFileName,publicParameterFileName,pidFileName,pkFileName,aggSignFileName,signFileName,messages);
            long end3 = System.currentTimeMillis();
            System.out.print("聚合验证的时间为：");
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

