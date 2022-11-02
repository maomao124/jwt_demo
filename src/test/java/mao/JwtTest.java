package mao;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;

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


}
