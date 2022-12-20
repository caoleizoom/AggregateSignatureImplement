package ref11;

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



public class ref11{
    //------------------------------------系统初始化--------------------------------
    public static void setup(String pairingFile, String publicFile,String mskFile) {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //设置KGC主私钥s
        Element s = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();
        mskProp.setProperty("s", Base64.getEncoder().encodeToString(s.toBytes()));
        storePropToFile(mskProp, mskFile);

        //设置主公钥K_pub,T_pub和公开参数
        Element P = bp.getG1().newRandomElement().getImmutable();
        Element P_pub = P.powZn(s).getImmutable();
        Properties pubProp = new Properties();
        pubProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
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

    public static void keygen(String pairingFile, String publicFile, String mskFile, String pidFile,String pkFile ,String skFile, String localFile) throws NoSuchAlgorithmException, IOException {
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
        Element k = bp.getZr().newRandomElement().getImmutable();
        Element r_ = bp.getZr().newRandomElement().getImmutable();
        Element beta_ = bp.getZr().newRandomElement().getImmutable();
        Element qeta_ = bp.getZr().newRandomElement().getImmutable();
        Element R_ = P.powZn(r_).getImmutable();
        Element PKrtsa = P.powZn(k).getImmutable();
        byte[] h2_hash = sha1(pid.toString()+P_pub.toString()+PKrtsa.toString()+R_.toString());
        Element alpha_ = bp.getZr().newElementFromHash(h2_hash,0,h2_hash.length).getImmutable();
        String under =  System.currentTimeMillis() + "";
        byte[] h3_hash = sha1(under);
        Element t_ = bp.getZr().newElementFromHash(h3_hash,0,h3_hash.length).getImmutable();
        Element T_ = t_.mul(beta_).getImmutable();
        Element A_ = P.powZn(qeta_).getImmutable().getImmutable();
        Element s_ = qeta_.add(alpha_.mul(s)).getImmutable();



        //车辆的操作：
        if(P.powZn(s_).isEqual(A_.add(P_pub.powZn(alpha_)))) {
            Element x_ = bp.getZr().newRandomElement().getImmutable();
            Element PK_ = P.powZn(x_).getImmutable();
            //设置私钥
            Properties skProp = new Properties();
            skProp.setProperty("A_", Base64.getEncoder().encodeToString(A_.toBytes()));
            skProp.setProperty("s_", Base64.getEncoder().encodeToString(s_.toBytes()));
            skProp.setProperty("x_", Base64.getEncoder().encodeToString(x_.toBytes()));
            //设置公钥
            Properties pkProp = new Properties();
            pkProp.setProperty("PK_", Base64.getEncoder().encodeToString(PK_.toBytes()));

            FileReader reader = new FileReader(publicFile);
            Properties Save = new Properties();
            Save.load(reader);
            Save.setProperty("PKrtsa", Base64.getEncoder().encodeToString(PKrtsa.toBytes()));
            FileWriter writer = new FileWriter(publicFile);
            Save.store(writer, "新增信息");
            reader.close();
            writer.close();

            //本地保存参数alpha,T_,R_,A_
            Properties localProp = new Properties();
            localProp.setProperty("r_",Base64.getEncoder().encodeToString(r_.toBytes()));
            localProp.setProperty("A_",Base64.getEncoder().encodeToString(A_.toBytes()));
            localProp.setProperty("under",under);
            localProp.setProperty("R_",Base64.getEncoder().encodeToString(R_.toBytes()));
            localProp.setProperty("T_",Base64.getEncoder().encodeToString(T_.toBytes()));
            localProp.setProperty("alpha_",Base64.getEncoder().encodeToString(alpha_.toBytes()));

            //存储公私钥
            storePropToFile(skProp, skFile);
            storePropToFile(pkProp, pkFile);
            storePropToFile(localProp,localFile);
        }else{
            System.out.println("密钥生成失败！");
        }
    }

    //--------------------------------IdentityAuthentication Phase------------------------------------------------
    public static void sign(String pairingFile, String publicFile, String pkFile, String skFile, String localFile, String pidFile ,String message, String signFile, int index) throws NoSuchAlgorithmException, IOException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //取出公开参数P
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String P_pubStr = pubProp.getProperty("P_pub");
        String PKrtdaStr = pubProp.getProperty("PKrtsa");
        Element P= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubStr)).getImmutable();
        Element PKrtsa= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PKrtdaStr)).getImmutable();

        //取出假名
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();

        //取出公钥
        Properties pkProp = loadPropFromFile(pkFile);
        String PK_Str = pkProp.getProperty("PK_");
        Element PK_= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK_Str)).getImmutable();

        //取出签名的私钥vsk，psk
        Properties skProp = loadPropFromFile(skFile);
        String s_Str = skProp.getProperty("s_");
        String x_Str = skProp.getProperty("x_");
        Element s_= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_Str)).getImmutable();
        Element x_= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x_Str)).getImmutable();
        //取出本地参数
        Properties localProp = loadPropFromFile(localFile);
        String alphaStr = localProp.getProperty("alpha_");
        String RStr = localProp.getProperty("R_");
        String under = localProp.getProperty("under");
        String TStr = localProp.getProperty("T_");
        String rStr = localProp.getProperty("r_");
        Element alpha_ = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(alphaStr)).getImmutable();
        Element R_ = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();
        Element T_ = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(TStr)).getImmutable();
        Element r_ = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(rStr)).getImmutable();

        //计算签名
        byte[] h4_hash = sha1(pid.toString()+message+alpha_.toString()+PK_.toString()+PKrtsa.toString()+P_pub.toString()+T_.toString()+R_.toString());
        Element h_ = bp.getZr().newElementFromHash(h4_hash,0,h4_hash.length).getImmutable();
        byte[] h5_hash = sha1(message+PK_.toString()+under+T_.toString()+R_.toString());
        Element delta_ = bp.getZr().newElementFromHash(h5_hash,0,h5_hash.length).getImmutable();
        Element sigma_ = r_.add(h_.mul(delta_.mul(x_).add(s_))).getImmutable();

        //保存签名
        FileReader reader = new FileReader(signFile);
        Properties signSave = new Properties();
        signSave.load(reader);
        signSave.setProperty("R_"+ index, Base64.getEncoder().encodeToString(R_.toBytes()));
        signSave.setProperty("sigma_"+ index, Base64.getEncoder().encodeToString(sigma_.toBytes()));
        FileWriter writer = new FileWriter(signFile);
        signSave.store(writer, "新增信息");
        reader.close();
        writer.close();
    }


    public static void verify(String pairingFile, String publicFile ,String pidFile ,String pkFile,String localFile ,String message, String sigFile ) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //获取生成元P和主公钥P_pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String P_pubStr = pubProp.getProperty("P_pub");
        String PKrtsaStr = pubProp.getProperty("PKrtsa");
        Element PKrtsa = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PKrtsaStr)).getImmutable();
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubStr)).getImmutable();

        //获取假名
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();
        //获取公钥vpk
        Properties pkProp = loadPropFromFile(pkFile);
        String PK_Str = pkProp.getProperty("PK_");
        Element PK_ = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK_Str)).getImmutable();

        //获取签名
        Properties signProp = loadPropFromFile(sigFile);
        String R_Str = signProp.getProperty("R_"+1);
        String sigma_Str = signProp.getProperty("sigma_"+1);
        Element R_ = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(R_Str)).getImmutable();
        Element sigma_ = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sigma_Str)).getImmutable();

        //获取local数据
        Properties localProp = loadPropFromFile(localFile);
        String alpha_Str = localProp.getProperty("alpha_");
        String T_Str = localProp.getProperty("T_");
        String A_Str = localProp.getProperty("A_");
        String under = localProp.getProperty("under");
        Element alpha_ = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(alpha_Str)).getImmutable();
        Element T_ = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(T_Str)).getImmutable();
        Element A_ = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(A_Str)).getImmutable();

        //验证签名
        byte[] h4_hash = sha1(pid.toString()+message+alpha_.toString()+PK_.toString()+PKrtsa.toString()+P_pub.toString()+T_.toString()+R_.toString());
        Element h_ = bp.getZr().newElementFromHash(h4_hash,0,h4_hash.length).getImmutable();

        byte[] h5_hash = sha1(message+PK_.toString()+under+T_.toString()+R_.toString());
        Element delta_ = bp.getZr().newElementFromHash(h5_hash,0,h5_hash.length).getImmutable();

        Element Q1 = PK_.powZn(h_.mul(delta_)).getImmutable();
        Element Q2 = A_.powZn(h_).getImmutable();
        Element Q3 = P_pub.powZn(h_.mul(alpha_)).getImmutable();
        if (P.powZn(sigma_).isEqual(R_.add(Q1.add(Q2.add(Q3))))){
            System.out.println(message + "：" + "签名验证成功！");
        }else{
            System.out.println(message + "：" + "签名验证失败！");
        }
    }

    public static  void aggreGate(String pairingFile, String signFile, String aggSignFile)throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingFile);
        Properties sigProp = loadPropFromFile(signFile);
        //计算聚合签名
        Element aggsigma = bp.getZr().newZeroElement().getImmutable();
        for (int i = 0 ; i<sigProp.size()/2 ; i++){
            String sigmaStr = sigProp.getProperty("sigma_" + i);
            Element sigma_ = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sigmaStr)).getImmutable();
            aggsigma = aggsigma.add(sigma_).getImmutable();
        }

        //保存聚合签名
        Properties saveAgg = new Properties();
        saveAgg.setProperty("aggsigma",Base64.getEncoder().encodeToString(aggsigma.toBytes()));
        storePropToFile(saveAgg,aggSignFile);
    }

    public static  void aggreGateVerify(String pairingFile, String publicFile, String pidFile, String localFile, String pkFile, String aggSignFile,String sigFile ,String[] messages) throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //获取生成元P和主公钥P_pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String P_pubStr = pubProp.getProperty("P_pub");
        String PKrtsaStr = pubProp.getProperty("PKrtsa");
        Element PKrtsa = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PKrtsaStr)).getImmutable();
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubStr)).getImmutable();

        //获取假名
        Properties pidProp = loadPropFromFile(pidFile);
        String pidStr = pidProp.getProperty("pid");
        Element pid = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(pidStr)).getImmutable();
        //获取公钥vpk
        Properties pkProp = loadPropFromFile(pkFile);
        String PK_Str = pkProp.getProperty("PK_");
        Element PK_ = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK_Str)).getImmutable();

        //获取聚合签名
        Properties aggsignProp = loadPropFromFile(aggSignFile);
        String aggsigma_Str = aggsignProp.getProperty("aggsigma");
        Element aggsigma = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(aggsigma_Str)).getImmutable();

        //获取local数据
        Properties localProp = loadPropFromFile(localFile);
        String alpha_Str = localProp.getProperty("alpha_");
        String T_Str = localProp.getProperty("T_");
        String A_Str = localProp.getProperty("A_");
        String under = localProp.getProperty("under");
        Element alpha_ = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(alpha_Str)).getImmutable();
        Element T_ = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(T_Str)).getImmutable();
        Element A_ = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(A_Str)).getImmutable();

        //验证签名
        Element R = bp.getG1().newZeroElement().getImmutable();
        Element h_deta_PK = bp.getG1().newZeroElement().getImmutable();
        Element hA = bp.getG1().newZeroElement().getImmutable();
        Element h_alpha = bp.getZr().newZeroElement();

        for (int i = 0 ;i< messages.length;i++){
            Properties sigProp = loadPropFromFile(sigFile);
            String R_Str = sigProp.getProperty("R_"+i);
            Element R_ = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(R_Str)).getImmutable();

            byte[] h4_hash = sha1(pid.toString()+messages[i]+alpha_.toString()+PK_.toString()+PKrtsa.toString()+P_pub.toString()+T_.toString()+R_.toString());
            Element h_ = bp.getZr().newElementFromHash(h4_hash,0,h4_hash.length).getImmutable();

            byte[] h5_hash = sha1(messages[i]+PK_.toString()+under+T_.toString()+R_.toString());
            Element delta_ = bp.getZr().newElementFromHash(h5_hash,0,h5_hash.length).getImmutable();

            R = R.add(R_).getImmutable();
            h_deta_PK = h_deta_PK.add(PK_.powZn(h_.mul(delta_)));
            hA = hA.add(A_.powZn(h_));
            h_alpha = h_alpha.add(h_.mul(alpha_));
        }

        if(P.powZn(aggsigma).isEqual(R.add(h_deta_PK.add(hA.add(P_pub.powZn(h_alpha)))))){
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
        String [] messages  =new String[] {"密码学","12345678","计算机","张无忌","计算机学院","密码学","12345678","计算机","张无忌","计算机科学学院","密码学","12345678","计算机","张无忌","计算机科学学院","密码学","12345678","计算机","张无忌","计算机科学学院"};
        String dir = "data_ref11/";
        String pairingParametersFileName = "data_ref11/a.properties";
        String publicParameterFileName = dir + "pub.properties";
        String pidFileName = dir + "pid.properties";
        String mskFileName = dir + "msk.properties";
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "sk.properties";
        String signFileName = dir + "sign.properties";
        String aggSignFileName = dir + "agg.properties";
        String localFileName = dir + "local.properties";

        setup(pairingParametersFileName,publicParameterFileName,mskFileName);
        pseudo(pairingParametersFileName,ridAlice,pidFileName);
        keygen(pairingParametersFileName,publicParameterFileName,mskFileName,pidFileName,pkFileName,skFileName,localFileName);
        System.out.println(messages.length);
        for(int i = 0 ; i<messages.length;i++){
            long start1 = System.currentTimeMillis();
            sign(pairingParametersFileName,publicParameterFileName,pkFileName,skFileName,localFileName,pidFileName,messages[i],signFileName,i);
            long end1 = System.currentTimeMillis();
            System.out.print("签名时间:");
            System.out.println(end1-start1);
        }
        for (int i =0;i<10;i++){
            long start2 = System.currentTimeMillis();
            verify(pairingParametersFileName,publicParameterFileName,pidFileName,pkFileName,localFileName,messages[1],signFileName);
            long end2 = System.currentTimeMillis();
            System.out.print("验证时间:");
            System.out.println(end2-start2);
        }
        aggreGate(pairingParametersFileName,signFileName,aggSignFileName);
        for (int i =0;i<10;i++){
            long start3 = System.currentTimeMillis();
            aggreGateVerify(pairingParametersFileName,publicParameterFileName,pidFileName,localFileName,pkFileName,aggSignFileName,signFileName,messages);
            long end3 = System.currentTimeMillis();
            System.out.print("聚合验证时间:");
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

