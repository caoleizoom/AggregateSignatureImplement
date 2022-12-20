package ref10;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.python.antlr.ast.Str;
import java.io.*;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;

import java.nio.ByteBuffer;

public class ref10 {

    public static void setup(String pairingParametersFileName, String publicParametersFileName, String mskFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        //设置主私钥s
        Element s = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();
        mskProp.setProperty("s", Base64.getEncoder().encodeToString(s.toBytes()));
        storePropToFile(mskProp, mskFileName);

        //设置主公钥T_pub和公开参数
        Element g = bp.getG1().newRandomElement().getImmutable();
        Element T_pub = g.powZn(s).getImmutable();
        Properties pubProp = new Properties();
        pubProp.setProperty("g", Base64.getEncoder().encodeToString(g.toBytes()));
        pubProp.setProperty("T_pub", Base64.getEncoder().encodeToString(T_pub.toBytes()));
        storePropToFile(pubProp, publicParametersFileName);
    }
    public static void pseGen(String pairingParametersFileName, String publicParametersFileName,String mskFileName ,String rid, String pidFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        // 用户的操作：选择k，计算pid1=kp，然后将 Rid 与 Pid 发送给TRA
        Element k = bp.getZr().newRandomElement().getImmutable();
        Properties pubProp = loadPropFromFile(publicParametersFileName);
        String gString = pubProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        Element pid1 = g.powZn(k).getImmutable();

//        Properties skProp = new Properties();
//        skProp.setProperty("k", Base64.getEncoder().encodeToString(k.toBytes()));
//        storePropToFile(skProp, skFileName);
        Properties idProp = new Properties();
        idProp.setProperty("rid", rid);
        idProp.setProperty("pid1", Base64.getEncoder().encodeToString(pid1.toBytes()));


        //TRA的操作：计算假名pid2
        Properties mskProp = loadPropFromFile(mskFileName);
        String sString = mskProp.getProperty("s");
        Element s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sString)).getImmutable();
        Element vp = bp.getG1().newRandomElement().getImmutable();
        byte[] ridByte = rid.getBytes();
        byte[] pid2 = new byte[ridByte.length];
        byte[] h0= sha1(bp.pairing(pid1.powZn(s),vp).toString());
        //System.out.println(ridByte.length);
        //System.out.println(h0.length);
        for (int i = 0; i < ridByte.length; i++){
            pid2[i] = (byte)(ridByte[i] ^ h0[i]);
        }
        idProp.setProperty("pid2", Base64.getEncoder().encodeToString(pid2));
        idProp.setProperty("vp", Base64.getEncoder().encodeToString(vp.toBytes()));
        storePropToFile(idProp, pidFileName);
    }


    public static void keygen(String pairingParametersFileName, String publicParametersFileName, String mskFileName, String pidFileName, String pkFileName ,String skFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        //取出主私钥s
        Properties mskProp = loadPropFromFile(mskFileName);
        String sString = mskProp.getProperty("s");
        Element s= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sString)).getImmutable();

        //公共参数g，T_pub
        Properties pubProp = loadPropFromFile(publicParametersFileName);
        String gString = pubProp.getProperty("g");
        String T_pubString = pubProp.getProperty("T_pub");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        Element T_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T_pubString)).getImmutable();

        // 取出假名pid2
        Properties pidProp = loadPropFromFile(pidFileName);
        String pid2String = pidProp.getProperty("pid2");
        Element pid2= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pid2String)).getImmutable();

        //计算psk=sQ,其中Q=H(pid2)
        byte[] idHash = sha1(pid2.toString());
        Element Q = bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();
        Element psk = Q.powZn(s).getImmutable();


        Properties skSave = new Properties();
        Properties pkSave = new Properties();
        //检查 e(psk,g) =? e(Q,T_pub)
        //System.out.println(bp.pairing(psk ,g));
        //System.out.println(bp.pairing(Q ,T_pub));
        if (bp.pairing(psk ,g).isEqual(bp.pairing(Q ,T_pub))){
            skSave.setProperty("psk", Base64.getEncoder().encodeToString(psk.toBytes()));
        }
        //计算vpk
        Element vsk = bp.getZr().newRandomElement().getImmutable();
        Element vpk = g.powZn(vsk).getImmutable();
        skSave.setProperty("vsk", Base64.getEncoder().encodeToString(vsk.toBytes()));
        pkSave.setProperty("vpk", Base64.getEncoder().encodeToString(vpk.toBytes()));
        storePropToFile(skSave, skFileName);
        storePropToFile(pkSave, pkFileName);
    }

    public static void sign(String pairingParametersFileName, String publicParametersFileName, String pkFileName, String skFileName, String pidFileName,  String message, String sigFileName, int index) throws NoSuchAlgorithmException, IOException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        //取出公开参数g
        Properties pubProp = loadPropFromFile(publicParametersFileName);
        String gString = pubProp.getProperty("g");
        Element g= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();

        //取出vpk
        Properties pkProp = loadPropFromFile(pkFileName);
        String pkString = pkProp.getProperty("vpk");
        Element vpk= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkString)).getImmutable();

        //取出签名的私钥vsk，psk
        Properties skProp = loadPropFromFile(skFileName);
        String vskString = skProp.getProperty("vsk");
        String pskString = skProp.getProperty("psk");
        Element vsk= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(vskString)).getImmutable();
        Element psk= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pskString)).getImmutable();



        //取出假名 rid,pid2
        Properties pidProp = loadPropFromFile(pidFileName);
        String pid2String = pidProp.getProperty("pid2");
        String rid  = pidProp.getProperty("rid");
        Element pid2= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pid2String)).getImmutable();


        //计算签名
        byte [] idHash = sha1(rid);
        Element Hj =  bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();
        Element Si =  psk.add(Hj.powZn(vsk));

        Element r = bp.getZr().newRandomElement().getImmutable();
        // h(m,PID,r,vsk)
        byte[] input1 = joinByteArray4(message.getBytes(),pid2.toString().getBytes(),r.toString().getBytes(),vsk.toString().getBytes());

        Element alpha = bp.getZr().newElementFromHash(input1,0,input1.length).getImmutable();
        Element R = g.powZn(alpha.mul(r));
        //h(m,PID,vpk,R,rid)
        byte[] input2 = joinByteArray5(message.getBytes(),pid2.toString().getBytes(),vpk.toString().getBytes(),R.toString().getBytes(),rid.getBytes());
        Element hi = bp.getZr().newElementFromHash(input2,0,input2.length).getImmutable();
        Element T = Hj.powZn(alpha.mul(r)).add(Si.powZn(hi));


        //保存签名
        FileReader reader = new FileReader("data_ref10/sign.properties");
        Properties signSave = new Properties();
        signSave.load(reader);
        signSave.setProperty("R"+ index, Base64.getEncoder().encodeToString(R.toBytes()));
        signSave.setProperty("T"+ index, Base64.getEncoder().encodeToString(T.toBytes()));


        FileWriter writer = new FileWriter("data_ref10/sign.properties");
        signSave.store(writer, "新增信息");
        reader.close();
        writer.close();
    }

        //storePropToFile(signSave, sigFileName);

    public static boolean verify(String pairingParametersFileName, String publicParametersFileName, String rid ,String pidFileName ,String pkFileName, String message, String sigFileName ) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        //获取公开参数和公钥vpk
        Properties pkProp = loadPropFromFile(pkFileName);
        Properties pubProp = loadPropFromFile(publicParametersFileName);
        String gString = pubProp.getProperty("g");
        String T_pubString = pubProp.getProperty("T_pub");
        String vpkString = pkProp.getProperty("vpk");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        Element T_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T_pubString)).getImmutable();
        Element vpk= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(vpkString)).getImmutable();

        //获取假名pid2
        Properties pidProp = loadPropFromFile(pidFileName);
        String pid2String = pidProp.getProperty("pid2");
        Element pid2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pid2String)).getImmutable();
        //获取签名
        Properties signProp = loadPropFromFile(sigFileName);
        String RString = signProp.getProperty("R"+1);
        Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RString)).getImmutable();
        String TString = signProp.getProperty("T"+1);
        Element T = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TString)).getImmutable();

        //验证签名
        byte [] idHash = sha1(rid);
        Element Hj =  bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();
        byte[] pidHash = sha1(pid2.toString());
        Element Q = bp.getG1().newElementFromHash(pidHash, 0, idHash.length).getImmutable();
        byte[] input = joinByteArray5(message.getBytes(),pid2.toString().getBytes(),vpk.toString().getBytes(),R.toString().getBytes(),rid.getBytes());
        Element hi = bp.getZr().newElementFromHash(input,0,input.length).getImmutable();

        if (bp.pairing(g,T).isEqual(bp.pairing(T_pub,Q.powZn(hi)).mul(bp.pairing(Hj,R.add(vpk.powZn(hi)))))){
            return true;
        }else {
            return false;
        }
    }

    public static  void aggreGate(String pairingParametersFileName,  String signFileName, String aggSignFileName)throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties sigProp = loadPropFromFile(signFileName);
        Element aggR = bp.getG1().newZeroElement().getImmutable();
        Element aggT = bp.getG1().newZeroElement().getImmutable();
        for (int i = 0 ; i<sigProp.size()/2 ; i++){
            String TString = sigProp.getProperty("T"+i);
            Element T = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TString)).getImmutable();
            aggT = aggT.add(T);
        }
        for (int i = 0 ; i<sigProp.size()/2 ; i++){
            String RString = sigProp.getProperty("R"+i);
            Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RString)).getImmutable();
            aggR = aggR.add(R);
        }

        //计算聚合签名
        Properties saveAgg = new Properties();
        saveAgg.setProperty("aggR",Base64.getEncoder().encodeToString(aggR.toBytes()));
        saveAgg.setProperty("aggT", Base64.getEncoder().encodeToString(aggT.toBytes()));
        storePropToFile(saveAgg,aggSignFileName);
    }

    public static  boolean aggreGateVerify(String pairingParametersFileName, String publicParametersFileName, String pidFileName, String pkFileName, String aggSignFileName, String signFileName,String[] messages, String rid) throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        //获取G1群生成元g和主公钥
        Properties pubProp = loadPropFromFile(publicParametersFileName);
        String gString = pubProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String T_pubString = pubProp.getProperty("T_pub");
        Element T_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T_pubString)).getImmutable();

        //获取假名
        Properties pidProp = loadPropFromFile(pidFileName);
        String pid2String = pidProp.getProperty("pid2");
        Element pid2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pid2String)).getImmutable();


        // 获取用户公钥
        Properties pkProp = loadPropFromFile(pkFileName);
        String vpkString = pkProp.getProperty("vpk");
        Element vpk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(vpkString)).getImmutable();

        //获取聚合签名
        Properties aggProp = loadPropFromFile(aggSignFileName);
        String aggRStr = aggProp.getProperty("aggR");
        String aggTStr = aggProp.getProperty("aggT");
        Element aggR = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(aggRStr)).getImmutable();
        Element aggT = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(aggTStr)).getImmutable();


        //验证聚合签名
        //计算Hj和Q
        byte [] idHash = sha1(rid);
        Element Hj =  bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();
        byte[] pidHash = sha1(pid2.toString());
        Element Q = bp.getG1().newElementFromHash(pidHash, 0, idHash.length).getImmutable();

        Properties rProp = loadPropFromFile(signFileName);
        Element hiQi = bp.getG1().newZeroElement().getImmutable();
        Element hivpk = bp.getG1().newZeroElement().getImmutable();
        for(int i=0;i<messages.length;i++){
            String RStr = rProp.getProperty("R"+i);
            Element R =  bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();
            byte[] hash = joinByteArray5(messages[i].getBytes(),pid2.toString().getBytes(),vpk.toString().getBytes(),R.toString().getBytes(),rid.getBytes());
            Element hi = bp.getZr().newElementFromHash(hash,0,hash.length).getImmutable();
            hiQi = hiQi.add(Q.powZn(hi));
            hivpk = hivpk.add(vpk.powZn(hi));
        }

        //验证聚合签名
        if(bp.pairing(g,aggT).isEqual(bp.pairing(T_pub,hiQi).mul(bp.pairing(Hj,aggR.add(hivpk))))){
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
    public static byte[] joinByteArray4(byte[] byte1, byte[] byte2, byte[] byte3, byte[] byte4) {

        return ByteBuffer.allocate(byte1.length + byte2.length + byte3.length + byte4.length)
                .put(byte1)
                .put(byte2)
                .put(byte3)
                .put(byte4)
                .array();
    }
    public static byte[] joinByteArray5(byte[] byte1, byte[] byte2, byte[] byte3, byte[] byte4, byte[] byte5) {

        return ByteBuffer.allocate(byte1.length + byte2.length + byte3.length + byte4.length+ byte5.length)
                .put(byte1)
                .put(byte2)
                .put(byte3)
                .put(byte4)
                .put(byte5)
                .array();
    }
        public static void main(String[] args) throws Exception {

        String idAlice = "alice@example123.com";
        String [] messages  =new String[] {"密码学","12345678","计算机","张无忌","计算机科学学院","密码学","12345678","计算机","张无忌","计算机科学学院","密码学","12345678","计算机","张无忌","计算机科学学院","密码学","12345678","计算机","张无忌","计算机科学学院"};
        String dir = "data_ref10/";
        String pairingParametersFileName = "data_ref10/a.properties";
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
            long start = System.currentTimeMillis();
            sign(pairingParametersFileName,publicParameterFileName,pkFileName,skFileName,pidFileName,messages[i],signFileName,i);
            long end = System.currentTimeMillis();
            System.out.print("签名时间：");
            System.out.println(end-start);
            }
        for (int i = 0; i<10;i++){
            long start1 = System.currentTimeMillis();
            boolean res = verify(pairingParametersFileName,publicParameterFileName,idAlice,pidFileName,pkFileName,messages[1],signFileName);
            System.out.println(res);
            long end1 = System.currentTimeMillis();
            System.out.print("验证时间：");
            System.out.println(end1-start1);
            }
        aggreGate(pairingParametersFileName,signFileName,aggSignFileName);
        for(int i = 0;i<10;i++){
            long start2 = System.currentTimeMillis();
            boolean aggverRes = aggreGateVerify(pairingParametersFileName,publicParameterFileName,pidFileName,pkFileName,aggSignFileName,signFileName,messages,idAlice);
            System.out.println(aggverRes);
            long end2 = System.currentTimeMillis();
            System.out.print("聚合签名验证：");
            System.out.println(end2-start2);

        }

        //System.out.println("当前程序运行多少毫秒:" + "=" + (end-start));

    }

}
