package com.fhl.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private UserDetailsService userDetailsService;
	@Autowired
	private BCryptPasswordEncoder  bCryptPasswordEncoder;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//On dit a Spring que l'authentification sera basee sur userDetailsService
		auth.userDetailsService(userDetailsService)
// Specification de la fonction du hashage utiliser pour coder le password
		.passwordEncoder(bCryptPasswordEncoder);
	}
//====================================================================================================================	

	@Override
	protected void configure(HttpSecurity http) throws Exception {
// desactivation de CSRF Synchronised token
		http.csrf().disable();
// Indiquer a Spring de ne pas creer une session
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//utiliser page login de spring
		http.formLogin();
// Utiliser page login personaliser
	       //http.formLogin().loginPage("/login");		
// Ajouter des regle d'autorisation
		http.authorizeRequests().antMatchers(HttpMethod.POST,"/tasks/**").hasAuthority("ADMIN");
		http.authorizeRequests().antMatchers(HttpMethod.POST,"/addRole/**").hasAuthority("ADMIN");
// Pour autoriser aux users d'acceder a la page de login et page registre 		
		http.authorizeRequests().antMatchers("/login/**", "/register/**").permitAll();
// toutes les requetes doivent etre authentifier
		 http.authorizeRequests().anyRequest().authenticated();
// Ajouter le filter JWT Authentification
		 http.addFilter(new JWTAuthenticationFilter(authenticationManager()));
// Ajouter le filter JWT Authorization
		 http.addFilterBefore(new JWTAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

      //  http.authorizeRequests().antMatchers("/entreprises", "/editEntreprise", "/taxes").hasRole("USER");
	 //	http.exceptionHandling().accessDeniedPage("/403");

	}

}
