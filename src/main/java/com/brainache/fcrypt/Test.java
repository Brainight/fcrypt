package com.brainache.fcrypt;

import com.brainache.fcrypt.derivation.FCryptKDFunction;
import com.brainache.utils.ByteGod;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Random;

/**
 *
 * @author Brainight
 */
public class Test {

    public static void main(String[] args) {
//        byte[] data = FCrypt.derivator(FCryptKDFunction.PBKDF2_WITH_HMAC_SHA256).hide("Password".toCharArray());
//        data[7] = 0x34;
//        FResult res = FCrypt.verifier(FCryptKDFunction.PBKDF2_WITH_HMAC_SHA256).verify("Password".toCharArray(), ByteGod.byteArrayToCharArrayBE255(data));
//        System.out.println(new String(data, StandardCharsets.UTF_8));
//        if(!res.isValid()){
//            System.out.println(res.getMsg());
//        }
//        
//        System.out.println(new String(data, StandardCharsets.UTF_8));
//        System.out.println(new String(((FCryptHashData)res.getTarget()).value(), StandardCharsets.UTF_8));
        byte[] data = FCrypt.derivator(FCryptKDFunction.BRAINIGHT_V1).hide("Password".toCharArray());
        System.out.println(ByteGod.getUTF8(data));
        FResult res = FCrypt.verifier(FCryptKDFunction.BRAINIGHT_V1).verify("Password".toCharArray(), ByteGod.byteArrayToCharArrayBE255(data));
        System.out.println(new String(data, StandardCharsets.UTF_8));
        if (!res.isValid()) {
            System.out.println(res.getMsg());
        }

    }

    public static void profile() {
//        System.out.println(FCrypt.getSupportedVersionsString());
//        byte[] data = FCrypt.derivator(FCryptKDFunction.PBKDF2_WITH_HMAC_SHA256).hide("Password".toCharArray());
//        System.out.println(new String(data, StandardCharsets.UTF_8));

//        Random r = new Random();
//        int numTests = 300;
//        String[] tests = new String[numTests];
//        long mineTotal = 0;
//        long javaTotal = 0;
//        int mineWins = 0;
//        Map<String, Map.Entry<String, Long>> mineResults = new HashMap<>();
//        Map<String, Map.Entry<String, Long>> javaResults = new HashMap<>();
//        tests[0] = "A";
//        for (int i = 1; i < numTests; i++) {
//            byte[] data = new byte[(int) Math.round(Math.random() * 200f) + 5];
//            r.nextBytes(data);
//            tests[i] = new String(data, StandardCharsets.UTF_8);
//        }
//
//        System.out.println("Starting MINE test...");
//        mineTotal = exec(true, tests, mineResults);
//        System.out.println("Ending MINE test...");
//        System.out.println("Starting JAVA test...");
//        javaTotal = exec(false, tests, javaResults);
//        System.out.println("Ending JAVA test...");
//
//        System.out.println("######### RESULTS ##########");
//        for (String key : mineResults.keySet()) {
//            System.out.println("-------------------------------");
//            System.out.println("STRING: " + key);
//            System.out.println("MINE => t:" + mineResults.get(key).getValue() + " => " + mineResults.get(key).getKey());
//            System.out.println("JAVA => t:" + javaResults.get(key).getValue() + " => " + javaResults.get(key).getKey());
//            System.out.println("DIFF: " + Math.abs(mineResults.get(key).getValue() - javaResults.get(key).getValue()));
//            System.out.println("WINNER: " + (mineResults.get(key).getValue() < javaResults.get(key).getValue() ? "MINE" : "JAVA"));
//            mineWins += mineResults.get(key).getValue() < javaResults.get(key).getValue() ? 1 : 0;
//            System.out.println("-------------------------------");
//        }
//        System.out.println("RESULT: Mine=" + mineTotal + "vs. Java=" + javaTotal);
//        System.out.println("Winner: " + (mineTotal < javaTotal ? "MINE" : "JAVA"));
//        System.out.println("Difference: " + Math.abs(mineTotal - javaTotal) + "ns");
//
//        System.out.println("Average MINE: " + mineTotal / numTests + "ns");
//        System.out.println("Average JAVA: " + javaTotal / numTests + "ns");
//        System.out.println("MINE WINS: " + mineWins + "/" + numTests);
    }

    public static long exec(boolean mine, String[] strs, Map<String, Map.Entry<String, Long>> result) {
        Random r = new Random();
        long total = 0;
        Map.Entry<String, Long> res = null;
        for (int i = 0; i < strs.length; i++) {

            if (mine) {
                res = execMine(strs[i]);
            } else {
                res = execJavas(strs[i]);
            }
            result.put(strs[i], res);
            total += res.getValue();
        }

        System.out.println("Total time " + ((mine) ? "MINE" : "JAVA") + ": " + total + "ns");
        return total;
    }

    public static Map.Entry<String, Long> execMine(String data) {
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        long res = 0;
        long start = System.nanoTime();
        byte[] result = ByteGod.encodeB64(bytes, false);
        res = System.nanoTime() - start;
        String strRes = new String(result, StandardCharsets.UTF_8);
        //System.out.println("#MINE => Time: " + res + "ns | String: " + data + " | Result: " + strRes);
        return Map.entry(strRes, res);
    }

    public static Map.Entry<String, Long> execJavas(String data) {
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        long res = 0;
        long start = System.nanoTime();
        byte[] result = Base64.getEncoder().encode(bytes);
        res = System.nanoTime() - start;
        String strRes = new String(result, StandardCharsets.UTF_8);
        //System.out.println("#JAVA => Time: " + res + "ns | String: " + data + " | Result: " + strRes);
        return Map.entry(strRes, res);
    }

}
