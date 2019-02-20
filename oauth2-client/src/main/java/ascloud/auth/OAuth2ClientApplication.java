package ascloud.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;

import ascloud.auth.conf.OAuth2LogoutHandler;

@SpringBootApplication
@EnableEurekaClient
@EnableZuulProxy
public class OAuth2ClientApplication {

	public static void main(String[] args) {
		SpringApplication.run(OAuth2ClientApplication.class, args);
	}

	@Bean
	public OAuth2RestTemplate oauth2RestTemplate(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext context) {
		return new OAuth2RestTemplate(resource, context);
	}

	@Bean
	public RoleHierarchy roleHierarchy() {
		RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
		roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_STAFF > ROLE_USER" + System.getProperty("line.separator")
				+ "ROLE_A > ROLE_B > ROLE_C");
		return roleHierarchy;
	}

	@Configuration
	@EnableOAuth2Sso
	static class WebSecurityConfig extends WebSecurityConfigurerAdapter {

		@Value("${ascloud.auth.server.logout-uri}")
		private String logoutUrl;

		@Autowired
		private OAuth2LogoutHandler oauth2LogoutHandler;

		@Autowired
		private RoleHierarchy roleHierarchy;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http//
					.authorizeRequests().antMatchers("/", "/login**").permitAll().anyRequest().authenticated().and()//
					.logout().addLogoutHandler(this.oauth2LogoutHandler).logoutSuccessUrl(this.logoutUrl);
		}

		@Override
		public void configure(WebSecurity web) throws Exception {
			OAuth2WebSecurityExpressionHandler expressionHandler = new OAuth2WebSecurityExpressionHandler();
			expressionHandler.setRoleHierarchy(this.roleHierarchy);
			web.expressionHandler(expressionHandler).ignoring().antMatchers("/actuator/**");
		}

	}
}
