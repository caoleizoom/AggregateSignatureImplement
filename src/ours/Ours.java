package ours;
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
import java.util.Map;
import java.util.Properties;
import org.python.core.PyString;
import org.python.util.PythonInterpreter;
import org.python.core.PyFunction;
import org.python.core.PyObject;


public class Ours{
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
        Element K_pub = P.powZn(s).getImmutable();
        Properties pubProp = new Properties();
        pubProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pubProp.setProperty("K_pub", Base64.getEncoder().encodeToString(K_pub.toBytes()));
        storePropToFile(pubProp, publicFile);
    }




    //---------------------------注册阶段-----------------------------------
    public static void keygen(String pairingFile, String publicFile, String mskFile, String rid, String fuzzyFile,String pkFile ,String skFile) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //公共参数群G生成元P,和主公钥Pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PubStr = pubProp.getProperty("K_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element K_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PubStr)).getImmutable();

        //用户操作:
        Element x = bp.getZr().newRandomElement().getImmutable();
        Element X = P.powZn(x).getImmutable();
        //调用模糊提取器
        PyObject pyObject = FextGen(rid);
        Map fuzzy = (Map) pyObject;
        String A = fuzzy.get("key").toString();
        String B = fuzzy.get("helper").toString();
        Properties fuzzyProp = new Properties();
        fuzzyProp.setProperty("A",A);
        fuzzyProp.setProperty("B",B);
        storePropToFile(fuzzyProp,fuzzyFile);


        //KGC的操作:
        //取出主私钥s
        Properties mskProp = loadPropFromFile(mskFile);
        String sString = mskProp.getProperty("s");
        Element s= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sString)).getImmutable();

        //生成部分私钥
        Element r = bp.getZr().newRandomElement().getImmutable();
        Element R = P.powZn(r).getImmutable();
        byte [] h1_hash = sha1(A+R.toString()+X.toString());
        Element h1 = bp.getZr().newElementFromHash(h1_hash,0,h1_hash.length).getImmutable();
        Element d = r.add(s.mul(h1));


        //车辆的操作：
        //设置私钥
        Properties skProp = new Properties();
        skProp.setProperty("x",Base64.getEncoder().encodeToString(x.toBytes()));
        skProp.setProperty("d",Base64.getEncoder().encodeToString(d.toBytes()));

        //设置公钥
        Properties pkProp = new Properties();
        pkProp.setProperty("X",Base64.getEncoder().encodeToString(X.toBytes()));
        pkProp.setProperty("R",Base64.getEncoder().encodeToString(R.toBytes()));
        //存储公私钥
        storePropToFile(skProp,skFile);
        storePropToFile(pkProp,pkFile);
        }

//--------------------------------IdentityAuthentication Phase------------------------------------------------
    public static void sign(String pairingFile, String publicFile, String pkFile, String skFile, String fuzzyFile ,  String message, String signFile, int index) throws NoSuchAlgorithmException, IOException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //取出公开参数P
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        Element P= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();

        Properties fuzzyProp = loadPropFromFile(fuzzyFile);
        String A = fuzzyProp.getProperty("A");

        //取出公钥
        Properties pkProp = loadPropFromFile(pkFile);
        String XStr = pkProp.getProperty("X");
        String RStr = pkProp.getProperty("R");
        Element X= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XStr)).getImmutable();
        Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();

        //取出签名的私钥x，d
        Properties skProp = loadPropFromFile(skFile);
        String xStr = skProp.getProperty("x");
        String dStr = skProp.getProperty("d");
        Element x= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xStr)).getImmutable();
        Element d= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(dStr)).getImmutable();

        //计算签名
        Element u = bp.getZr().newRandomElement().getImmutable();
        Element U = P.powZn(u).getImmutable();
        byte[] h2_hash = sha1(message+A+X.toString()+U.toString());
        Element h2 = bp.getZr().newElementFromHash(h2_hash,0,h2_hash.length);
        byte[] h3_hash = sha1(message+A+R.toString()+U.toString());
        Element h3 = bp.getZr().newElementFromHash(h3_hash,0,h3_hash.length);
        Element sigma = u.add(x.mul(h2).add(d.mul(h3)));

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
        signSave.setProperty("sigma"+ index, Base64.getEncoder().encodeToString(sigma.toBytes()));
        FileWriter writer = new FileWriter(signFile);
        signSave.store(writer, "新增信息");
        reader.close();
        writer.close();
    }


    public static boolean verify(String pairingFile, String publicFile ,String pid ,String fuzzyFile,String pkFile, String message, String sigFile ) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //获取生成元P和主公钥K_pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String P_pubStr = pubProp.getProperty("K_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element K_pub= bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubStr)).getImmutable();

        //获取helper,计算A
        Properties fuzzyProp = loadPropFromFile(fuzzyFile);
        String B = fuzzyProp.getProperty("B");
        String A = FextRep(pid,B).toString();

        //获取公钥pk=(X,R)
        Properties pkProp = loadPropFromFile(pkFile);
        String XStr = pkProp.getProperty("X");
        String RStr = pkProp.getProperty("R");
        Element X = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XStr)).getImmutable();
        Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();

        //获取签名
        Properties signProp = loadPropFromFile(sigFile);
        String UStr = signProp.getProperty("U"+1);
        String SigmaStr = signProp.getProperty("sigma"+1);
        Element U = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(UStr)).getImmutable();
        Element sigma = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(SigmaStr)).getImmutable();

        //验证签名
        byte[] h1_hash = sha1(A+R.toString()+X.toString());
        Element h1 = bp.getZr().newElementFromHash(h1_hash,0,h1_hash.length).getImmutable();

        byte[] h2_hash = sha1(message+A+X.toString()+U.toString());
        Element h2 = bp.getZr().newElementFromHash(h2_hash,0,h2_hash.length).getImmutable();

        byte[] h3_hash = sha1(message+A+R.toString()+U.toString());
        Element h3 = bp.getZr().newElementFromHash(h3_hash,0,h3_hash.length).getImmutable();
        if (P.powZn(sigma).isEqual(U.add(X.powZn(h2).add(R.powZn(h3).add(K_pub.powZn(h1.mul(h3))))))){
            return true;
        }else{
            return false;
        }
    }

    public static  void aggreGate(String pairingFile, String signFile, String aggSignFile)throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingFile);
        Properties sigProp = loadPropFromFile(signFile);
        //计算聚合签名
        Element aggSigma = bp.getZr().newZeroElement().getImmutable();
        for (int i = 0 ; i<sigProp.size()/2 ; i++){
            String SigmaStr = sigProp.getProperty("sigma"+i);
            Element sigma = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(SigmaStr)).getImmutable();
            aggSigma = aggSigma.add(sigma).getImmutable();
        }

        //保存聚合签名
        Properties saveAgg = new Properties();
        saveAgg.setProperty("aggSigma",Base64.getEncoder().encodeToString(aggSigma.toBytes()));
        storePropToFile(saveAgg,aggSignFile);
    }

    public static  boolean aggreGateVerify(String pairingFile, String publicFile, String pid, String fuzzyFile, String pkFile, String aggSignFile, String signFile,String[] messages) throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //获取G1群生成元P和主公钥P_pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String K_pubStr = pubProp.getProperty("K_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element K_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(K_pubStr)).getImmutable();

        //获取A
        Properties fuzzyProp = loadPropFromFile(fuzzyFile);
        String B = fuzzyProp.getProperty("B");
        //String A = FextRep(pid,B).toString();
        String A = fuzzyProp.getProperty("A");


        // 获取用户公钥
        Properties pkProp = loadPropFromFile(pkFile);
        String XStr = pkProp.getProperty("X");
        String RStr = pkProp.getProperty("R");
        Element X = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XStr)).getImmutable();
        Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();

        //获取聚合签名
        Properties aggProp = loadPropFromFile(aggSignFile);
        String aggSStr = aggProp.getProperty("aggSigma");
        Element aggSigma = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(aggSStr)).getImmutable();


        //验证聚合签名
        byte [] h1_hash = sha1(A+R.toString()+X.toString());
        Element h1 =  bp.getZr().newElementFromHash(h1_hash, 0, h1_hash.length).getImmutable();

        Element U = bp.getG1().newZeroElement().getImmutable();
        Element h2X = bp.getG1().newZeroElement().getImmutable();
        Element h3R = bp.getG1().newZeroElement().getImmutable();
        Element h1h3Kpub = bp.getG1().newZeroElement().getImmutable();
        for (int i=0;i<messages.length;i++){
            Properties uProp = loadPropFromFile(signFile);
            String uString = uProp.getProperty("U"+i);
            Element Ui = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(uString)).getImmutable();
            U = U.add(Ui).getImmutable();

            byte[] h2_hash = sha1(messages[i]+A+X.toString()+Ui.toString());
            Element h2 = bp.getZr().newElementFromHash(h2_hash,0,h2_hash.length);
            h2X = h2X.add(X.powZn(h2));

            byte[] h3_hash = sha1(messages[i]+A+R.toString()+Ui.toString());
            Element h3 = bp.getZr().newElementFromHash(h3_hash,0,h3_hash.length);
            h3R = h3R.add(R.powZn(h3));

            h1h3Kpub = h1h3Kpub.add(K_pub.powZn(h1.mul(h3)));
        }
        if(P.powZn(aggSigma).isEqual(U.add(h2X.add(h3R.add(h1h3Kpub))))){
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
    public static PyObject FextGen(String rid){
        PythonInterpreter pythonInterpreter = new PythonInterpreter();
        pythonInterpreter.execfile("pythonFile/fuzzyGen.py");
        PyFunction pyFunction = pythonInterpreter.get("Gen", PyFunction.class);
        PyObject pyobj = pyFunction.__call__(new PyString(rid));
        return pyobj;
    }
    public static PyObject FextRep(String pid, String helper){
        PythonInterpreter pythonInterpreter = new PythonInterpreter();
        pythonInterpreter.execfile("pythonFile/fuzzyRep.py");
        PyFunction pyFunction = pythonInterpreter.get("Rep", PyFunction.class);
        PyObject pyobj = pyFunction.__call__(new PyString(pid),new PyString(helper));
        return pyobj;
    }
    public static void main(String[] args) throws Exception {
        String ridAlice = "AABBCCDDEEFFGGHH";
        String pidAlice = "AABBCCKDEEMFGGHI";
        String [] messages  =new String[] {"密码学","12345678","计算机","张无忌","计算机学院","密码学","12345678","计算机","张无忌","计算机学院"};
        String dir = "data_ours/";
        String pairingParametersFileName = "data_ours/a.properties";
        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String fuzzyFileName = dir + "fu.properties";
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "sk.properties";
        String signFileName = dir + "sign.properties";
        String aggSignFileName = dir + "agg.properties";


        setup(pairingParametersFileName,publicParameterFileName,mskFileName);
        keygen(pairingParametersFileName,publicParameterFileName,mskFileName,ridAlice,fuzzyFileName,pkFileName,skFileName);
        System.out.println(messages.length);
        for(int i = 0 ; i<messages.length;i++){
            long start1 = System.currentTimeMillis();
            sign(pairingParametersFileName,publicParameterFileName,pkFileName,skFileName,fuzzyFileName,messages[i],signFileName,i);
            long end1 = System.currentTimeMillis();
            System.out.print("签名的时间为：");
            System.out.println(end1-start1);
        }
        for (int i =0; i< 10;i++){
            long start2 = System.currentTimeMillis();
            boolean res = verify(pairingParametersFileName,publicParameterFileName,pidAlice,fuzzyFileName,pkFileName,messages[1],signFileName);
            long end2 = System.currentTimeMillis();
            System.out.print(res);
            System.out.print("验证的时间为：");
            System.out.println(end2-start2);
        }
        aggreGate(pairingParametersFileName,signFileName,aggSignFileName);
        for(int i = 0;i<10;i++){
            long start3 = System.currentTimeMillis();
            boolean aggverRes = aggreGateVerify(pairingParametersFileName,publicParameterFileName,pidAlice,fuzzyFileName,pkFileName,aggSignFileName,signFileName,messages);
            long end3 = System.currentTimeMillis();
            System.out.print("聚合签名的时间为：");
            System.out.println(end3-start3);
            System.out.println(aggverRes);
        }
    }

}
