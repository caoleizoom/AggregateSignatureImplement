package ref12;

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

import java.nio.ByteBuffer;

public class ref12 {
    //------------------------------------系统初始化--------------------------------
    public static void setup(String pairingFile, String publicFile,String mskFile) {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //设置KGC主私钥s和TA主私钥b
        Element s = bp.getZr().newRandomElement().getImmutable();
        Element b = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();
        mskProp.setProperty("s", Base64.getEncoder().encodeToString(s.toBytes()));
        mskProp.setProperty("b", Base64.getEncoder().encodeToString(b.toBytes()));
        storePropToFile(mskProp, mskFile);

        //设置主公钥T_pub和公开参数
        Element P = bp.getG1().newRandomElement().getImmutable();
        Element P_pub = P.powZn(s).getImmutable();
        Element T_pub = P.powZn(b).getImmutable();
        Properties pubProp = new Properties();
        pubProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pubProp.setProperty("P_pub", Base64.getEncoder().encodeToString(P_pub.toBytes()));
        pubProp.setProperty("T_pub", Base64.getEncoder().encodeToString(T_pub.toBytes()));
        storePropToFile(pubProp, publicFile);
    }


    //-------------------------------------生成假名-------------------------------------------
    public static void pseGen(String pairingFile, String publicFile,String mskFile ,String rid, String pidFile) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //获取公开参数
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String T_pubStr = pubProp.getProperty("T_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element T_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T_pubStr)).getImmutable();


        // 用户的操作：选择t，计算pid1=tP，K=tT_pub,然后将 pid1 与 K 发送给TA
        Element t = bp.getZr().newRandomElement().getImmutable();
        Element pid1 = P.powZn(t).getImmutable();

        byte[] ridByte = rid.getBytes();
        byte[] K = new byte[128];  //20位
        byte[] tT = T_pub.powZn(t).toBytes();  //128位
        K = tT;
        for (int i = 0; i < ridByte.length; i++) {
            K[i] = (byte) (ridByte[i] ^ tT[i]);
        }
        //为了方便仿真，生成假名的具体操作省略
        Element pid = bp.getZr().newRandomElement().getImmutable();
        Properties pidProp = new Properties();
        pidProp.setProperty("pid", Base64.getEncoder().encodeToString(pid.toBytes()));
        storePropToFile(pidProp, pidFile);
    }


    public static void keygen(String pairingFile, String publicFile, String mskFile, String pidFile, String pkFile ,String skFile) throws NoSuchAlgorithmException {
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
        String sString = mskProp.getProperty("s");
        Element s= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sString)).getImmutable();
        // 取出假名pid
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();
        //生成部分私钥
        Element r = bp.getZr().newRandomElement().getImmutable();
        Element R = P.powZn(r).getImmutable();
        byte [] h1_hash = sha1(pid.toString()+R.toString()+P_pub.toString());
        //byte[] h1_hash = joinByteArray3(pid.toString().getBytes(),R.toString().getBytes(),P_pub.toString().getBytes());

        Element h1 = bp.getZr().newElementFromHash(h1_hash,0,h1_hash.length).getImmutable();
        Element psk = r.add(s.mul(h1));


        //车辆的操作：
        //验证
        if(P.powZn(psk).isEqual(R.add(P_pub.powZn(h1)))){  //验证通过
            Element vsk = bp.getZr().newRandomElement().getImmutable();
            Element X = P.powZn(vsk).getImmutable();
            byte[] h2_hash = sha1(pid.toString()+X.toString());
            //byte [] h2_hash = joinByteArray2(pid.toString().getBytes(),X.toString().getBytes());
            Element h2 = bp.getZr().newElementFromHash(h2_hash,0,h2_hash.length).getImmutable();
            Element Q = R.add(X.powZn(h2)).getImmutable();

            //设置私钥
            Properties skProp = new Properties();
            skProp.setProperty("psk",Base64.getEncoder().encodeToString(psk.toBytes()));
            skProp.setProperty("vsk",Base64.getEncoder().encodeToString(vsk.toBytes()));

            //设置公钥
            Properties pkProp = new Properties();
            pkProp.setProperty("Q",Base64.getEncoder().encodeToString(Q.toBytes()));
            pkProp.setProperty("R",Base64.getEncoder().encodeToString(R.toBytes()));
            //存储公私钥
            storePropToFile(skProp,skFile);
            storePropToFile(pkProp,pkFile);
        }
    }

    public static void sign(String pairingFile, String publicFile, String pkFile, String skFile, String pidFile,  String message, String signFile, int index) throws NoSuchAlgorithmException, IOException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //取出公开参数P
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        Element P= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();

        //取出假名 pid
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();

        //取出公钥
        Properties pkProp = loadPropFromFile(pkFile);
        String QStr = pkProp.getProperty("Q");
        String RStr = pkProp.getProperty("R");
        Element Q= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QStr)).getImmutable();
        Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();

        //取出签名的私钥vsk，psk
        Properties skProp = loadPropFromFile(skFile);
        String vskStr = skProp.getProperty("vsk");
        String pskStr = skProp.getProperty("psk");
        Element vsk= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(vskStr)).getImmutable();
        Element psk= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(pskStr)).getImmutable();

        //计算签名
        Element X = P.powZn(vsk).getImmutable();
        Element u = bp.getZr().newRandomElement().getImmutable();
        Element U = P.powZn(u).getImmutable();
        byte[] h2_hash = sha1(pid.toString()+X.toString());
        Element h2 = bp.getZr().newElementFromHash(h2_hash,0,h2_hash.length);
        byte[] h3_hash = sha1(pid.toString()+message+Q.toString()+R.toString()+U.toString());
        Element h3 = bp.getZr().newElementFromHash(h3_hash,0,h3_hash.length);
        Element S = u.add(h3.mul(psk.add(h2.mul(vsk)))).getImmutable();

//        保存签名
//        Properties saveSig = new Properties();
//        saveSig.setProperty("U",Base64.getEncoder().encodeToString(U.toBytes()));
//        saveSig.setProperty("S",Base64.getEncoder().encodeToString(S.toBytes()));
//        storePropToFile(saveSig,signFile);
//
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


    public static boolean verify(String pairingFile, String publicFile ,String pidFile ,String pkFile, String message, String sigFile  ) throws NoSuchAlgorithmException {
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

        //获取公钥vpk=(Q,R)
        Properties pkProp = loadPropFromFile(pkFile);
        String QStr = pkProp.getProperty("Q");
        String RStr = pkProp.getProperty("R");
        Element Q = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QStr)).getImmutable();
        Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();

        //获取签名
        Properties signProp = loadPropFromFile(sigFile);
        String UStr = signProp.getProperty("U"+1);
        String SStr = signProp.getProperty("S"+1);
        Element U = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(UStr)).getImmutable();
        Element S = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(SStr)).getImmutable();

        //验证签名
        byte[] h1_hash = sha1(pid.toString()+R.toString()+P_pub.toString());
        Element h1 = bp.getZr().newElementFromHash(h1_hash,0,h1_hash.length).getImmutable();
        byte[] h3_hash = sha1(pid.toString()+message+Q.toString()+R.toString()+U.toString());
        Element h3 = bp.getZr().newElementFromHash(h3_hash,0,h3_hash.length).getImmutable();
        if (P.powZn(S).isEqual(U.add(Q.powZn(h3).add(P_pub.powZn(h1.mul(h3)))))){
            return true;
        }else {
            return false;
        }
    }

    public static  void aggreGate(String pairingFile, String signFile, String aggSignFile)throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingFile);
        Properties sigProp = loadPropFromFile(signFile);
        //计算聚合签名
        Element aggS = bp.getZr().newZeroElement().getImmutable();
        for (int i = 0 ; i<sigProp.size()/2 ; i++){
            String SStr = sigProp.getProperty("S"+i);
            Element S = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(SStr)).getImmutable();
            aggS = aggS.add(S).getImmutable();
        }

        //保存聚合签名
        Properties saveAgg = new Properties();
        saveAgg.setProperty("aggS",Base64.getEncoder().encodeToString(aggS.toBytes()));
        storePropToFile(saveAgg,aggSignFile);
    }

    public static  boolean aggreGateVerify(String pairingFile, String publicFile, String pidFile, String pkFile, String aggSignFile, String signFile,String[] messages) throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //获取G1群生成元P和主公钥P_pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String P_pubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubStr)).getImmutable();

        //获取假名
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();

        // 获取用户公钥
        Properties pkProp = loadPropFromFile(pkFile);
        String QStr = pkProp.getProperty("Q");
        String RStr = pkProp.getProperty("R");
        Element Q = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QStr)).getImmutable();
        Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();

        //获取聚合签名
        Properties aggProp = loadPropFromFile(aggSignFile);
        String aggSStr = aggProp.getProperty("aggS");
        Element aggS = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(aggSStr)).getImmutable();


        //验证聚合签名
        byte [] h1_hash = sha1(pid.toString()+R.toString()+P_pub.toString());
        Element h1 =  bp.getZr().newElementFromHash(h1_hash, 0, h1_hash.length).getImmutable();
        Element U = bp.getG1().newZeroElement().getImmutable();
        Element h3Q = bp.getG1().newZeroElement().getImmutable();
        Element h1h3Ppub = bp.getG1().newZeroElement().getImmutable();
        for (int i=0;i<messages.length;i++){
            Properties uProp = loadPropFromFile(signFile);
            String uString = uProp.getProperty("U"+i);
            Element Ui = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(uString)).getImmutable();
            U = U.add(Ui).getImmutable();

            byte[] h3_hash = sha1(pid.toString()+messages[i]+Q.toString()+R.toString()+Ui.toString());
            Element h3 = bp.getZr().newElementFromHash(h3_hash,0,h3_hash.length);
            h3Q = h3Q.add(Q.powZn(h3));

            h1h3Ppub = h1h3Ppub.add(P_pub.powZn(h1.mul(h3)));
        }
        if(P.powZn(aggS).isEqual(U.add(h3Q.add(h1h3Ppub)))){
            return true;
        }else {
            return false;
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
        String idAlice = "alice@example123.com";
        String [] messages  =new String[] {"密码学","12345678","计算机","张无忌","计算机科学学院","密码学","12345678","计算机","张无忌","计算机科学学院","密码学","12345678","计算机","张无忌","计算机科学学院","密码学","12345678","计算机","张无忌","计算机科学学院"};
        String dir = "data_ref12/";
        String pairingParametersFileName = "data_ref12/a.properties";
        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String pidFileName = dir + "pid.properties";
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "sk.properties";
        String signFileName = dir + "sign.properties";
        String aggSignFileName = dir + "agg.properties";


        setup(pairingParametersFileName,publicParameterFileName,mskFileName);
        pseGen(pairingParametersFileName,publicParameterFileName,mskFileName,idAlice,pidFileName);
        keygen(pairingParametersFileName,publicParameterFileName,mskFileName,pidFileName,pkFileName,skFileName);
        System.out.println(messages.length);
        for(int i = 0 ; i<messages.length;i++){
            long start1 = System.currentTimeMillis();
            sign(pairingParametersFileName,publicParameterFileName,pkFileName,skFileName,pidFileName,messages[i],signFileName,i);
            long end1 = System.currentTimeMillis();
            System.out.print("签名时间：");
            System.out.println(end1-start1);
        }
        for (int i = 0;i<10;i++){
            long start2 = System.currentTimeMillis();
            boolean res = verify(pairingParametersFileName,publicParameterFileName,pidFileName,pkFileName,messages[1],signFileName);
            System.out.print(res);
            long end2 = System.currentTimeMillis();
            System.out.print("验证时间：");
            System.out.println(end2-start2);
        }
       aggreGate(pairingParametersFileName,signFileName,aggSignFileName);
        for (int i =0;i<10;i++){
            long start3 = System.currentTimeMillis();
            boolean aggverRes = aggreGateVerify(pairingParametersFileName,publicParameterFileName,pidFileName,pkFileName,aggSignFileName,signFileName,messages);
            System.out.print(aggverRes);
            long end3 = System.currentTimeMillis();
            System.out.print("聚合验证时间：");
            System.out.println(end3-start3);
        }

//        System.out.println(aggverRes);
//        //System.out.println("当前程序运行多少毫秒:" + "=" + (end-start));

    }

}
