package cn.edu.xcu.jwttest.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.StringUtils;

import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * JWT 工具类（HS253 算法）
 *
 * @author iWeJang
 * @version 2.0
 */
public class JWTUtil {
    /**
     * 秘钥
     */
    @Value("${app.jwt.secret}")
    private static final String TOKEN_SECRET = "token!@#$%^7890";
    /**
     * 有效期，30分钟
     */
    @Value("${app.jwt.expire}")
    private static final long EXPIRE_TIME = 30 * 60 * 1000;

    /**
     * 生成 token
     *
     * @param claims 私有声明
     * @return 返回 token 字符串
     */
    public static String generate(Map<String, Object> claims) {
        try {
            // 设置过期时间
            Date date = new Date(System.currentTimeMillis() + EXPIRE_TIME);
            // 私钥和加密算法
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            // 设置头部信息
            Map<String, Object> header = new HashMap<>(2);
            header.put("typ", "jwt");
            header.put("alg", "HS253");
            // token字符串
            JWTCreator.Builder builder = JWT.create()
                    .withHeader(header)
                    .withIssuedAt(new Date()) //发证时间
                    .withExpiresAt(date);  //过期时间
            // 设置私有声明
            claims.forEach((key, value) -> {
                if (value instanceof Integer) {
                    builder.withClaim(key, (Integer) value);
                } else if (value instanceof Long) {
                    builder.withClaim(key, (Long) value);
                } else if (value instanceof Boolean) {
                    builder.withClaim(key, (Boolean) value);
                } else if (value instanceof String) {
                    builder.withClaim(key, String.valueOf(value));
                } else if (value instanceof Double) {
                    builder.withClaim(key, (Double) value);
                } else if (value instanceof Date) {
                    builder.withClaim(key, (Date) value);
                }
            });
            //签名并返回
            return builder.sign(algorithm);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 校验 token
     *
     * @param token 令牌
     */
    public static boolean verify(String token) {
        // 如果验证通过，则不会报错
        JWT.require(Algorithm.HMAC256(TOKEN_SECRET)).build().verify(token);
        return true;
    }

    /**
     * 获取私有声明
     */
    public static Map<String, Claim> getClaims(String token) {
        Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
        JWTVerifier verifier = JWT.require(algorithm).build();
        return verifier.verify(token).getClaims();
    }

    /**
     * 获取过期时间
     */
    public static Date getExpiresAt(String token) {
        Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
        return JWT.require(algorithm).build().verify(token).getExpiresAt();
    }

    /**
     * 获取 jwt 发证时间
     */
    public static Date getIssuedAt(String token) {
        Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
        return JWT.require(algorithm).build().verify(token).getIssuedAt();
    }

    /**
     * 检查 token 是否失效
     */
    public static boolean isExpired(String token) {
        try {
            final Date expiration = getExpiresAt(token);
            return expiration.before(new Date());
        } catch (TokenExpiredException e) {
            return true;
        }
    }

    /**
     * Base64 解密获取 header 内容
     */
    public static String getHeaderByBase64(String token) {
        if (StringUtils.hasText(token)) {
            return null;
        } else {
            byte[] header_byte = Base64.getDecoder().decode(token.split("\\.")[0]);
            return new String(header_byte);
        }
    }

    /**
     * Base64 解密获取 payload 内容
     */
    public static String getPayloadByBase64(String token) {
        if (StringUtils.hasText(token)) {
            return null;
        } else {
            byte[] payload_byte = Base64.getDecoder().decode(token.split("\\.")[1]);
            return new String(payload_byte);
        }
    }
}
