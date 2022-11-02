package mao;

import cn.hutool.core.io.FileUtil;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.Test;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Project name(项目名称)：jwt_demo
 * Package(包名): mao
 * Class(类名): JwtTest
 * Author(作者）: mao
 * Author QQ：1296193245
 * GitHub：https://github.com/maomao124/
 * Date(创建日期)： 2022/11/2
 * Time(创建时间)： 13:40
 * Version(版本): 1.0
 * Description(描述)： 无
 */

public class JwtTest
{

    /**
     * 生成token，不使用签名
     */
    @Test
    void test1()
    {
        Map<String, Object> head = new HashMap<>();
        head.put("alg", "none");
        head.put("typ", "JWT");

        Map<String, Object> body = new HashMap<>();
        body.put("userId", "10001");
        body.put("username", "张三");
        body.put("sex", "男");

        String token = Jwts.builder()
                .setHeader(head)
                .setClaims(body)
                .setId("jwt1")
                .compact();
        System.out.println(token);
        //eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMSIsImp0aSI6Imp3dDEiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9.
    }

    /**
     * 解析token，不使用签名
     */
    @Test
    void test2()
    {
        Jwt jwt = Jwts.parser().parse("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0." +
                "eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMSIsImp0aSI6Imp3dDEiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9.");
        Header header = jwt.getHeader();
        Object body = jwt.getBody();
        System.out.println(jwt);
        System.out.println(header);
        System.out.println(body);
    }


    /**
     * 生成token，使用hs256签名算法
     */
    @Test
    void test3()
    {
        Map<String, Object> head = new HashMap<>();
        head.put("alg", SignatureAlgorithm.HS256.getValue());
        head.put("typ", "JWT");

        Map<String, Object> body = new HashMap<>();
        body.put("userId", "10002");
        body.put("username", "张三");
        body.put("sex", "男");

        String token = Jwts.builder()
                .setHeader(head)
                .setClaims(body)
                .setId("jwt2")
                .signWith(SignatureAlgorithm.HS256, "123456")
                .compact();
        System.out.println(token);
        //eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
        // .eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMiIsImp0aSI6Imp3dDIiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9
        // .9TC0U77uYueqnUdU_we2yVUZ6uj9mrsLPhjr4gB2v98
    }

    /**
     * 解析token，使用hs256签名算法，不设置SigningKey的情况
     */
    @Test
    void test4()
    {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" +
                ".eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMiIsImp0aSI6Imp3dDIiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9." +
                "9TC0U77uYueqnUdU_we2yVUZ6uj9mrsLPhjr4gB2v98";

        Jwt jwt = Jwts.parser()
                .parse(token);
        Header header = jwt.getHeader();
        Object body = jwt.getBody();
        System.out.println(jwt);
        System.out.println(header);
        System.out.println(body);
    }


    /**
     * 解析token，使用hs256签名算法，SigningKey错误的情况
     */
    @Test
    void test5()
    {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" +
                ".eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMiIsImp0aSI6Imp3dDIiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9." +
                "9TC0U77uYueqnUdU_we2yVUZ6uj9mrsLPhjr4gB2v98";

        Jwt jwt = Jwts.parser()
                .setSigningKey("1236")
                .parse(token);
        Header header = jwt.getHeader();
        Object body = jwt.getBody();
        System.out.println(jwt);
        System.out.println(header);
        System.out.println(body);
    }

    /**
     * 解析token，使用hs256签名算法，SigningKey正确的情况
     */
    @Test
    void test6()
    {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" +
                ".eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMiIsImp0aSI6Imp3dDIiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9." +
                "9TC0U77uYueqnUdU_we2yVUZ6uj9mrsLPhjr4gB2v98";

        Jwt jwt = Jwts.parser()
                .setSigningKey("123456")
                .parse(token);
        Header header = jwt.getHeader();
        Object body = jwt.getBody();
        System.out.println(jwt);
        System.out.println(header);
        System.out.println(body);
    }


    /**
     * 生成jwt令牌，基于RS256签名算法，错误
     */
    @Test
    void test7()
    {
        Map<String, Object> head = new HashMap<>();
        head.put("alg", SignatureAlgorithm.RS256.getValue());
        head.put("typ", "JWT");

        Map<String, Object> body = new HashMap<>();
        body.put("userId", "10003");
        body.put("username", "张三");
        body.put("sex", "男");

        String token = Jwts.builder()
                .setHeader(head)
                .setClaims(body)
                .setId("jwt3")
                .signWith(SignatureAlgorithm.RS256, "123456")
                .compact();
        System.out.println(token);
    }


    /**
     * 生成自己的 秘钥/公钥 对
     *
     * @throws Exception 异常
     */
    @Test
    public void test8() throws Exception
    {
        //自定义 随机密码,  请修改这里
        String password = "123456";

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom secureRandom = new SecureRandom(password.getBytes());
        keyPairGenerator.initialize(1024, secureRandom);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();

        FileUtil.writeBytes(publicKeyBytes, "./pub.key");
        FileUtil.writeBytes(privateKeyBytes, "./pri.key");
    }

    //获取私钥
    public PrivateKey getPriKey() throws Exception
    {
//        InputStream inputStream =
//                this.getClass().getClassLoader().getResourceAsStream("pri.key");
        FileInputStream inputStream = new FileInputStream("./pri.key");
        DataInputStream dataInputStream = new DataInputStream(inputStream);
        byte[] keyBytes = new byte[inputStream.available()];
        dataInputStream.readFully(keyBytes);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }

    //获取公钥
    public PublicKey getPubKey() throws Exception
    {
//        InputStream inputStream =
//                this.getClass().getClassLoader().getResourceAsStream("pub.key");
        FileInputStream inputStream = new FileInputStream("./pub.key");
        DataInputStream dataInputStream = new DataInputStream(inputStream);
        byte[] keyBytes = new byte[inputStream.available()];
        dataInputStream.readFully(keyBytes);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    /**
     * 生成jwt令牌，基于RS256签名算法
     */
    @Test
    void test9() throws Exception
    {
        Map<String, Object> head = new HashMap<>();
        head.put("alg", SignatureAlgorithm.RS256.getValue());
        head.put("typ", "JWT");

        Map<String, Object> body = new HashMap<>();
        body.put("userId", "10003");
        body.put("username", "张三");
        body.put("sex", "男");

        String token = Jwts.builder()
                .setHeader(head)
                .setClaims(body)
                .setId("jwt3")
                .signWith(SignatureAlgorithm.RS256, getPriKey())
                .compact();
        System.out.println(token);
        //eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwM
        // yIsImp0aSI6Imp3dDMiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9.Ke2o0WFNNQp71Sdd056bP2Z2
        // CywxfaV4M9OUtsPNBmrLWSLNOkqUao3DiTdX2kLMMWjVQ4THnCQHRiJhXa2uPX6qLfNPHh
        // CC1unYFBlU17WAPSfpp3BeEF4UK3G5GOiamLFghiowlwG84_3AuNFOj8JZXY4Beq_FpT9PSo1608M
    }

    /**
     * 解析jwt令牌，基于RS256签名算法
     */
    @Test
    void test10() throws Exception
    {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9" +
                ".eyJzZXgiOiLnlLciLCJ1c2VySWQiOiIxMDAwMyIsImp0aSI6Imp3dDMiLCJ1c2VybmFtZSI6IuW8oOS4iSJ9" +
                ".Ke2o0WFNNQp71Sdd056bP2Z2CywxfaV4M9OUtsPNBmrLWSLNOkqUao3DiTdX2kLMMWjVQ4" +
                "THnCQHRiJhXa2uPX6qLfNPHhCC1unYFBlU17WAPSfpp3BeEF4UK3G5GOiamLFghiowlwG84_3AuNFOj8JZXY4Beq_FpT9PSo1608M";

        Jwt jwt = Jwts.parser()
                .setSigningKey(getPubKey())
                .parse(token);
        Header header = jwt.getHeader();
        Object body = jwt.getBody();
        System.out.println(jwt);
        System.out.println(header);
        System.out.println(body);
    }

    /**
     * 生成jwt令牌，基于RS256签名算法，带过期时间，解析过期的情况
     */
    @Test
    void test11() throws Exception
    {
        Map<String, Object> head = new HashMap<>();
        head.put("alg", SignatureAlgorithm.RS256.getValue());
        head.put("typ", "JWT");

        Map<String, Object> body = new HashMap<>();
        body.put("userId", "10004");
        body.put("username", "张三");
        body.put("sex", "男");

        String token = Jwts.builder()
                .setHeader(head)
                .setClaims(body)
                .setExpiration(new Date(new Date().getTime() + 2 * 1000))//2秒
                .setId("jwt4")
                .signWith(SignatureAlgorithm.RS256, getPriKey())
                .compact();
        System.out.println(token);


        Thread.sleep(2000);

        Jwt jwt = Jwts.parser()
                .setSigningKey(getPubKey())
                .parse(token);
        Header header = jwt.getHeader();
        Object body2 = jwt.getBody();
        System.out.println(jwt);
        System.out.println(header);
        System.out.println(body2);
    }


    /**
     * 生成jwt令牌，基于RS256签名算法，带过期时间，解析没有过期的情况
     */
    @Test
    void test12() throws Exception
    {
        Map<String, Object> head = new HashMap<>();
        head.put("alg", SignatureAlgorithm.RS256.getValue());
        head.put("typ", "JWT");

        Map<String, Object> body = new HashMap<>();
        body.put("userId", "10004");
        body.put("username", "张三");
        body.put("sex", "男");

        String token = Jwts.builder()
                .setHeader(head)
                .setClaims(body)
                .setExpiration(new Date(new Date().getTime() + 2 * 1000))//2秒
                .setId("jwt4")
                .signWith(SignatureAlgorithm.RS256, getPriKey())
                .compact();
        System.out.println(token);


        //Thread.sleep(2000);

        System.out.println("\n-------\n");

        Jwt jwt = Jwts.parser()
                .setSigningKey(getPubKey())
                .parse(token);
        Header header = jwt.getHeader();
        Object body2 = jwt.getBody();
        System.out.println(jwt);
        System.out.println(header);
        System.out.println(body2);
    }
}
