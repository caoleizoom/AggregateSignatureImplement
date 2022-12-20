package ref09;

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



public class ref09{
    //------------------------------------系统初始化--------------------------------
    public static void setup(String pairingFile, String publicFile,String mskFile) {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //设置KGC主私钥s
        Element s = bp.getZr().newRandomElement().getImmutable();
        Element alpha = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();
        mskProp.setProperty("s", Base64.getEncoder().encodeToString(s.toBytes()));
        mskProp.setProperty("alpha", Base64.getEncoder().encodeToString(alpha.toBytes()));
        storePropToFile(mskProp, mskFile);

        //设置主公钥K_pub,T_pub和公开参数
        Element P = bp.getG1().newRandomElement().getImmutable();
        Element P_pub = P.powZn(s).getImmutable();
        Element T_pub = P.powZn(alpha).getImmutable();
        Properties pubProp = new Properties();
        pubProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pubProp.setProperty("T-pub", Base64.getEncoder().encodeToString(T_pub.toBytes()));
        pubProp.setProperty("P_pub", Base64.getEncoder().encodeToString(P_pub.toBytes()));
        storePropToFile(pubProp, publicFile);
    }

    public  static  void pseudo(String pairingFile,String rid, String pidFile ) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        byte[] rid_hash = sha1(rid);
        Element pid = bp.getG1().newElementFromHash(rid_hash,0,rid_hash.length);
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
        String PubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PubStr)).getImmutable();


        //KGC的操作:
        //取出主私钥s
        Properties mskProp = loadPropFromFile(mskFile);
        String sStr = mskProp.getProperty("s");
        Element s= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sStr)).getImmutable();
        //获取假名
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();

        //生成部分私钥
        byte [] h3_hash = sha1(pid.toString());
        Element Q = bp.getG1().newElementFromHash(h3_hash,0,h3_hash.length).getImmutable();
        Element psk = Q.powZn(s).getImmutable();


        //车辆的操作：
        if(bp.pairing(psk,P).isEqual(bp.pairing(Q,P_pub))) {
            Element x = bp.getZr().newRandomElement().getImmutable();
            Element vpk = P.powZn(x).getImmutable();
            //设置私钥
            Properties skProp = new Properties();
            skProp.setProperty("vsk", Base64.getEncoder().encodeToString(x.toBytes()));
            skProp.setProperty("psk", Base64.getEncoder().encodeToString(psk.toBytes()));

            //设置公钥
            Properties pkProp = new Properties();
            pkProp.setProperty("vpk", Base64.getEncoder().encodeToString(vpk.toBytes()));
            //存储公私钥
            storePropToFile(skProp, skFile);
            storePropToFile(pkProp, pkFile);
        }else{
            System.out.println("密钥生成失败！");
        }
    }

    //--------------------------------IdentityAuthentication Phase------------------------------------------------
    public static void sign(String pairingFile, String publicFile, String pkFile, String skFile,  String pidFile, String ID_Rj ,String message, String signFile, int index) throws NoSuchAlgorithmException, IOException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //取出公开参数P
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        Element P= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();

        //取出假名
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();



        //取出公钥
        Properties pkProp = loadPropFromFile(pkFile);
        String vpkStr = pkProp.getProperty("vpk");
        Element vpk= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(vpkStr)).getImmutable();

        //取出签名的私钥vsk，psk
        Properties skProp = loadPropFromFile(skFile);
        String vskStr = skProp.getProperty("vsk");
        String pskStr = skProp.getProperty("psk");
        Element vsk= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(vskStr)).getImmutable();
        Element psk= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pskStr)).getImmutable();

        //计算签名
        byte[] Hj_hash = sha1(ID_Rj);
        Element Hj = bp.getG1().newElementFromHash(Hj_hash,0,Hj_hash.length).getImmutable();
        Element S = psk.add(Hj.powZn(vsk)).getImmutable();
        Element r = bp.getZr().newRandomElement().getImmutable();
        Element R = P.powZn(r).getImmutable();
        byte[] h2_hash = sha1(message+pid.toString()+vpk.toString()+ID_Rj);
        Element hi = bp.getZr().newElementFromHash(h2_hash,0,h2_hash.length).getImmutable();
        Element T = Hj.powZn(r).add(S.powZn(hi)).getImmutable();

        //保存签名
        FileReader reader = new FileReader(signFile);
        Properties signSave = new Properties();
        signSave.load(reader);
        signSave.setProperty("R"+ index, Base64.getEncoder().encodeToString(R.toBytes()));
        signSave.setProperty("T"+ index, Base64.getEncoder().encodeToString(T.toBytes()));
        FileWriter writer = new FileWriter(signFile);
        signSave.store(writer, "新增信息");
        reader.close();
        writer.close();
    }


    public static void verify(String pairingFile, String publicFile ,String pidFile ,String ID_Rj ,String pkFile, String message, String sigFile ) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //获取生成元P和主公钥P_pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String P_pubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubStr)).getImmutable();

        //获取假名
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();
        //获取公钥vpk
        Properties pkProp = loadPropFromFile(pkFile);
        String vpkStr = pkProp.getProperty("vpk");
        Element vpk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(vpkStr)).getImmutable();

        //获取签名
        Properties signProp = loadPropFromFile(sigFile);
        String RStr = signProp.getProperty("R"+1);
        String TStr = signProp.getProperty("T"+1);
        Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();
        Element T = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TStr)).getImmutable();

        //验证签名
        byte[] h1_hash = sha1(ID_Rj);
        Element Hj = bp.getG1().newElementFromHash(h1_hash,0,h1_hash.length).getImmutable();

        byte[] h3_hash = sha1(pid.toString());
        Element Q = bp.getG1().newElementFromHash(h3_hash,0,h3_hash.length).getImmutable();

        byte[] h2_hash = sha1(message+pid.toString()+vpk.toString()+ID_Rj);
        Element hi = bp.getZr().newElementFromHash(h2_hash,0,h2_hash.length).getImmutable();

        if (bp.pairing(P,T).isEqual(bp.pairing(P_pub,Q.powZn(hi)).mul(bp.pairing(Hj,R.add(vpk.powZn(hi)))))){
            System.out.println(message + "：" + "签名验证成功！");
        }else{
            System.out.println(message + "：" + "签名验证失败！");
        }
    }

    public static  void aggreGate(String pairingFile, String signFile, String aggSignFile)throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingFile);
        Properties sigProp = loadPropFromFile(signFile);
        //计算聚合签名
        Element aggR = bp.getG1().newZeroElement().getImmutable();
        Element aggT = bp.getG1().newZeroElement().getImmutable();
        for (int i = 0 ; i<sigProp.size()/2 ; i++){
            String RStr = sigProp.getProperty("R" + i);
            String TStr = sigProp.getProperty("T" + i);
            Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();
            Element T = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TStr)).getImmutable();
            aggR = aggR.add(R).getImmutable();
            aggT = aggT.add(T).getImmutable();
        }

        //保存聚合签名
        Properties saveAgg = new Properties();
        saveAgg.setProperty("aggR",Base64.getEncoder().encodeToString(aggR.toBytes()));
        saveAgg.setProperty("aggT",Base64.getEncoder().encodeToString(aggT.toBytes()));
        storePropToFile(saveAgg,aggSignFile);
    }

    public static  void aggreGateVerify(String pairingFile, String publicFile, String pidFile, String ID_Rj, String pkFile, String aggSignFile,String[] messages) throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //获取G1群生成元P和主公钥P_pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String K_pubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(K_pubStr)).getImmutable();

        //获取用户假名
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();

        // 获取用户公钥
        Properties pkProp = loadPropFromFile(pkFile);
        String vpkStr = pkProp.getProperty("vpk");
        Element vpk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(vpkStr)).getImmutable();

        //获取聚合签名
        Properties aggProp = loadPropFromFile(aggSignFile);
        String aggRStr = aggProp.getProperty("aggR");
        String aggTStr = aggProp.getProperty("aggT");
        Element aggR = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(aggRStr)).getImmutable();
        Element aggT = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(aggTStr)).getImmutable();


        //验证聚合签名
        byte [] h1_hash = sha1(ID_Rj);
        Element Hj = bp.getG1().newElementFromHash(h1_hash,0,h1_hash.length);
        byte [] h3_hash = sha1(pid.toString());
        Element Q =  bp.getG1().newElementFromHash(h3_hash, 0, h3_hash.length).getImmutable();
        Element hiQ = bp.getG1().newZeroElement().getImmutable();
        Element hivpk = bp.getG1().newZeroElement().getImmutable();

        for (int i=0;i<messages.length;i++){
            byte[] h2_hash = sha1(messages[i]+pid.toString()+vpk.toString()+ID_Rj);
            Element hi = bp.getZr().newElementFromHash(h2_hash,0,h2_hash.length).getImmutable();
            hiQ = hiQ.add(Q.powZn(hi)).getImmutable();
            hivpk = hivpk.add(vpk.powZn(hi));
        }
        if(bp.pairing(P,aggT).isEqual(bp.pairing(P_pub,hiQ).mul(bp.pairing(Hj,aggR.add(hivpk))))){
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
        String dir = "data_ref09/";
        String pairingParametersFileName = "data_ref09/a.properties";
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
            sign(pairingParametersFileName,publicParameterFileName,pkFileName,skFileName,pidFileName,ID_Rj,messages[i],signFileName,i);
            long end1 = System.currentTimeMillis();
            System.out.print("签名时间:");
            System.out.println(end1-start1);
        }
        for (int i = 0; i<10 ; i++){
            long start2 = System.currentTimeMillis();
            verify(pairingParametersFileName,publicParameterFileName,pidFileName,ID_Rj,pkFileName,messages[1],signFileName);
            long end2 = System.currentTimeMillis();
            System.out.println(end2-start2);
        }
        aggreGate(pairingParametersFileName,signFileName,aggSignFileName);
        for (int i=0;i<10;i++){
            long start3 = System.currentTimeMillis();
            aggreGateVerify(pairingParametersFileName,publicParameterFileName,pidFileName,ID_Rj,pkFileName,aggSignFileName,messages);
            long end3 = System.currentTimeMillis();
            System.out.print("聚合签名时间:");
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

