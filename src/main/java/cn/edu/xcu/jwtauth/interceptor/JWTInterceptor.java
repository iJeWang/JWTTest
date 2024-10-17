package cn.edu.xcu.jwtauth.interceptor;

import cn.edu.xcu.jwtauth.utils.JWTUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * JWT 验证拦截器
 *
 * @author iWeJang
 * @version 1.0
 */
public class JWTInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler){
        //（令牌建议放在请求头中）获取请求头中的令牌
        final String token = request.getHeader("authorization");

        return JWTUtil.verify(token);
    }
}
