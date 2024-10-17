## 秘钥和有效期（application.yml）

## JWT 工具类（JWTUtil）

## JWT 拦截器（JWTInterceptor） + 路径配置（JWTWebConfig）

   拦截器校检 JWT 时并没有处理相关的异常，建议进行全局异常处理，或者在拦截器内增加相关的处理逻辑。
   默认拦截所有路径并排除```/index```和```/static/**```，可以根据需要重新配置。