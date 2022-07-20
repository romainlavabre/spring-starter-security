package com.replace.replace.api.security;

import com.fairfair.ag.api.environment.Environment;
import com.fairfair.ag.util.Cast;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
@Service
public class UserAccessResolverImpl implements com.fairfair.ag.api.security.UserAccessResolver {

    protected final Environment           environment;
    protected final JwtTokenHandler       jwtTokenHandler;
    protected final AuthenticationHandler authenticationHandler;


    public UserAccessResolverImpl(
            Environment environment,
            JwtTokenHandler jwtTokenHandler,
            AuthenticationHandler authenticationHandler ) {
        this.environment           = environment;
        this.jwtTokenHandler       = jwtTokenHandler;
        this.authenticationHandler = authenticationHandler;
    }


    @Override
    public User getUser( String token ) {

        Jws< Claims >  claims         = signAndGetClaims( token );
        Authentication authentication = this.authenticationHandler.getAuthentication( claims );
        SecurityContextHolder.getContext().setAuthentication( authentication );

        User user = new User();
        user.setId( Cast.getLong( claims.getBody().getSubject() ) );
        user.setUsername( claims.getBody().get( "username" ).toString() );
        for ( String role : claims.getBody().get( "roles", String.class ).toString().split( "," ) ) {
            user.addRole( role );
        }

        return user;
    }


    private Jws< Claims > signAndGetClaims( String token ) {
        return this.jwtTokenHandler.validateJwtToken( token );
    }
}
