package com.fhl.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class JWTAuthorizationFilter extends OncePerRequestFilter{
	
	

	public JWTAuthorizationFilter() {
		super();
		// TODO Auto-generated constructor stub
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response,
			FilterChain filterChain) throws ServletException, IOException {
		System.out.println("  *********JWT Authorization Filter***********");	
//================================================================================================== 		
//==Pour eviter le prob de CORS
		response.addHeader("Access-Control-Allow-Origin", "*");
//Access-Control-Allow-Headers : pour autoriser au client (App Frend-End) d'envoyer les entetes suivants:
		response.addHeader("Access-Control-Allow-Headers",
				  "Origin,"
				+ " Accept,"
				+ " X-Requested-With,"
				+ " Content-Type,"
				+ " Access-Control-Request-Method,"
				+ " Access-Control-Request-Headers,"
				+ " Authorization");
//== Access-Control-Expose-Headers : pour autoriser l'app Frent-End de lire les entetes suivants 
		response.addHeader("Access-Control-Expose-Headers",
				"Access-Control-Allow-Origin,"
			   + " Access-Control-Allow-Credentials,"
			   + " Authorization"
			   );
//===================================================================================================		
		if(request.getMethod().equals("OPTIONS")) {
			response.setStatus(HttpServletResponse.SC_OK);// SC_OK : Status Code=OK
			System.out.println("**** Requete OPTIONS a ete envoyee **** ");
		} else {
			String jwtToken=request.getHeader(SecurityConstants.HEADER_STRING);
			 System.out.println("token stocker dans l'entete : "+jwtToken);
			//== Si le token n'existe pas ou ne commence pas par le prefix Bearer
			   if(jwtToken==null || !jwtToken.startsWith(SecurityConstants.TOKEN_PREFIX))
			     { //-- On laisse Spring fait ce qu'il devait faire et on quitte
				   System.out.println("token est null ou il n'existe pas :**= "+jwtToken);
				   filterChain.doFilter(request, response);
				   return;
			        }
			   //== Sinon on va signer le token et on le recupere
			  
			   Claims claims=Jwts.parser()
					   .setSigningKey(SecurityConstants.SECRET)
					   //== Suppression du prefix Bearer
					   .parseClaimsJws(jwtToken.replace(SecurityConstants.TOKEN_PREFIX, ""))
					   //== pour recuperer le token signer
					   .getBody();
			//=== Le token signer est stocke dans le variable claims   
			   System.out.println("**** token Apres suppression du prefix ***** "+claims);
			   // Recuperer le username et ses roles a partir du tocken (claims)
			   String username=claims.getSubject();
			   // roles est un tableau d'objets c'est pour ca on a utilise une Collection de Map<cle,valeur>
			  /* "roles": [
			             {
			               "authority": "ADMIN"
			             },
			             {
			               "authority": "USER"
			             }
			           ]*/
			   ArrayList<Map<String,String>> roles= (ArrayList<Map<String, String>>) claims.get("roles");
			//Stocker les roleName dans la collection authorities
			   Collection<GrantedAuthority> authorities= new ArrayList<>();
			   roles.forEach(r->{
				   authorities.add(new SimpleGrantedAuthority(r.get("authority")));
			   });
			
			  //== null c'est pour le password car on a pas besoin car l'utilisateur est deja connecter auparavant.
			  // on utilise seulement son username et ses roles
			   
			  //==Creer le user authentifier qui a envoye le token
			   UsernamePasswordAuthenticationToken authenticationUser=
			   new UsernamePasswordAuthenticationToken(username,null,authorities);
			  
			   //== Charger le user authentifier dans le contexte de Spring Security
			   //== c-a-d : On dit a Spring Security Voila l'identites de l'utilisateur qui a envoyer le token
			   SecurityContextHolder.getContext().setAuthentication(authenticationUser);
			   filterChain.doFilter(request, response);	   
			
		}//== Fin Else
	
	}

}
