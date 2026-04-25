package org.sasanlabs.security.filter;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Global security headers filter that adds protective HTTP headers to all responses.
 *
 * <p>This filter adds the following security headers:
 *
 * <ul>
 *   <li>Content-Security-Policy - Prevents XSS and data injection attacks
 *   <li>X-Content-Type-Options: nosniff - Prevents MIME type sniffing
 *   <li>X-Frame-Options: DENY - Prevents clickjacking attacks
 *   <li>Strict-Transport-Security - Enforces HTTPS connections
 *   <li>Referrer-Policy: strict-origin-when-cross-origin - Controls referrer information
 * </ul>
 *
 * @author KSASAN preetkaran20@gmail.com
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SecurityHeadersFilter extends OncePerRequestFilter {

    private static final String CONTENT_SECURITY_POLICY =
            "default-src 'self'; "
                    + "script-src 'self'; "
                    + "style-src 'self' 'unsafe-inline'; "
                    + "img-src 'self' data:; "
                    + "font-src 'self'; "
                    + "connect-src 'self'; "
                    + "frame-ancestors 'none'; "
                    + "form-action 'self'; "
                    + "base-uri 'self'; "
                    + "object-src 'none';";

    private static final String X_CONTENT_TYPE_OPTIONS = "nosniff";
    private static final String X_FRAME_OPTIONS = "DENY";
    private static final String STRICT_TRANSPORT_SECURITY =
            "max-age=31536000; includeSubDomains; preload";
    private static final String REFERRER_POLICY = "strict-origin-when-cross-origin";
    private static final String X_XSS_PROTECTION = "1; mode=block";
    private static final String PERMISSIONS_POLICY = "geolocation=(), microphone=(), camera=()";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        // Content-Security-Policy
        response.setHeader("Content-Security-Policy", CONTENT_SECURITY_POLICY);

        // X-Content-Type-Options
        response.setHeader("X-Content-Type-Options", X_CONTENT_TYPE_OPTIONS);

        // X-Frame-Options
        response.setHeader("X-Frame-Options", X_FRAME_OPTIONS);

        // Strict-Transport-Security
        response.setHeader("Strict-Transport-Security", STRICT_TRANSPORT_SECURITY);

        // Referrer-Policy
        response.setHeader("Referrer-Policy", REFERRER_POLICY);

        // X-XSS-Protection (legacy but still useful for older browsers)
        response.setHeader("X-XSS-Protection", X_XSS_PROTECTION);

        // Permissions-Policy
        response.setHeader("Permissions-Policy", PERMISSIONS_POLICY);

        filterChain.doFilter(request, response);
    }
}
