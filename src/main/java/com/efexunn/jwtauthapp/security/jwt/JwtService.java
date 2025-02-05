package com.efexunn.jwtauthapp.security.jwt;

import com.efexunn.jwtauthapp.user.User;
import com.efexunn.jwtauthapp.user.UserService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {
    private final UserService userService;
    private static final String SECRET_KEY = "E5408068BC9BA6048BB1206EDD9F39643EE25A18896F373B74C9928A188852DD785762DF46DD7DC3DBDC422FDE9DEE76A99A9E44379E33C1809663649EC133C789912E42E473FE78F4BBBA3361747CA60434FBF349A628BEDB5BE6BE2F34EE4BF6CA814B8B2810978242028B61F0BCF9FE66CEEACF2E6AA8521F2163B4DEDFAC71EFB532C22FAECFDD4458796E8702946897AA300AFF1060CEF51C7F38ECD3304F8EAC6DF3A02A02BA4ED21605F1102E2137D720DAE8C060D3EC73DD4FDA1F308F83FBB1F9E73F03DE12AF1D8D4C7209A1379FC3214BB8DFB43AACBC41B5A907892156E4CA7ECDEBF2919AFDE8479572F0682A1BA3704A3180CAF23F2485EF939F7A1CB22666B1F320560599096BDF400890FE40D939D72B553661EEF08C895D41749F7FB1E29FE4C7ECED3F42CCD603FC46F60990D4FFFC07DF7DC32D278";
    private static final Long expirationTime = 60000L;



    public String extractUsername(String token) {
        return this.extractClaims(token, Claims::getSubject);
    }

    public <T> T extractClaims(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        return this.generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return buildToken(extraClaims, userDetails);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + this.expirationTime))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        try{
            return extractExpiration(token).before(new Date());
        }
        catch (ExpiredJwtException e){
            return true;
        }

    }

    private Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        try{
            return Jwts
                    .parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        }catch (ExpiredJwtException e){
            //log.error("expired jwt");
            return new DefaultClaims();
        }

    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public User GetUserByToken(String token){
        String jwt = token.replace("Bearer", "");

        String username = Jwts
                .parserBuilder()
                .setSigningKey(this.getSignInKey())
                .build()
                .parseClaimsJws(jwt)
                .getBody()
                .getSubject();

        User user = userService.findByEmail(username);
        return user;
    }
}