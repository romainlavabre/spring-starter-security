package com.replace.replace.api.security;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
public interface UserAccessResolver {

    User getUser( String token );
}
