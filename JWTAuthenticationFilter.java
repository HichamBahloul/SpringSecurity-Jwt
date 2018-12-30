package com.fhl.security;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fhl.entities.AppUser;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private AuthenticationManager authenticationManager;
//---------------------------------------------------------------------------------------		
	public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
		super();
		this.authenticationManager=authenticationManager;
	}
//---------------------------------------------------------------------------------------		
	@Override
	public Authentication attemptAuthentication(
			HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException {
		
		AppUser user=null;
		
		try {
//== ObjectMapper().readValue:
  //===Permet de prendre le corps de la requete(des objects Json) et les stocker dans
			//un objet java (AppUser): (de Jackson)		
			user= new ObjectMapper().readValue(request.getInputStream(), AppUser.class);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
//== Faire quelques affichage pour tester est qu'on a bien recuperer l'username et password
		//== envoyes par l'utilisateur
	System.out.println("  *********JWT Authentication Filter***********");	
	System.out.println(" username : "+user.getUsername());
	System.out.println(" password : "+user.getPassword());
//== Retourner a Spring Security on objet Authentication contenant l'username et password		
		return authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						user.getUsername(),
						user.getPassword()
						)
				);
		
	}//fin methode
//---------------------------------------------------------------------------------------	
	@Override
//== Une fois Spring Security authentifier l'utilisateur, il fait appel au successfulAuthentication()
//== Spring passe le resultat de l'authentication au filter a travers l'objet: authResult
//== SecurityConstants : Une classe qu'on a cree dans laquelle on definit des constantes	
	protected void successfulAuthentication(HttpServletRequest request,
			HttpServletResponse response,
			FilterChain chain,// Filtre de Spring Security
			Authentication authResult) throws IOException, ServletException {	
		System.out.println("  *********Appel successfulAuthentication ***********");
//== On recuper l'utilisateur qui est authentifier
		User springUser= (User) authResult.getPrincipal();
//== Creation du  token : Header + Payload + Signature
		String jwtToken=Jwts.builder()
//== Definition du Payload :	
				// sub :REgistred Claim
				.setSubject(springUser.getUsername())
				// exp :REgistred Claim
				.setExpiration(new Date(System.currentTimeMillis()+SecurityConstants.EXPIRATION_TIME))
				.claim("roles", springUser.getAuthorities())
//== Definition Header +Signature :				
				.signWith(SignatureAlgorithm.HS256, SecurityConstants.SECRET)
				//pour utiliser l'encodage Base64URL 
				.compact();	
//== On ajoute dans l'entete de la reponse le token 
		//== HEADER_STRING : Nom de l'entete				
			response.addHeader(SecurityConstants.HEADER_STRING,
					SecurityConstants.TOKEN_PREFIX+jwtToken);	
	}
//---------------------------------------------------------------------------------------		
	
}
