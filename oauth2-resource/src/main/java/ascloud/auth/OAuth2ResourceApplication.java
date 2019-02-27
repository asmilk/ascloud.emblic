package ascloud.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

@SpringBootApplication
@EnableEurekaClient
@EnableResourceServer
public class OAuth2ResourceApplication {

	public static void main(String[] args) {
		SpringApplication.run(OAuth2ResourceApplication.class, args);
	}

	@Bean
	public RoleHierarchy roleHierarchy() {
		RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
		roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_STAFF > ROLE_USER" + System.getProperty("line.separator")
				+ "ROLE_A > ROLE_B > ROLE_C");
		return roleHierarchy;
	}

//	@Configuration
//	@EnableResourceServer
//	static class ResourceServerConfig extends ResourceServerConfigurerAdapter {
//		
//		@Autowired
//		private RoleHierarchy roleHierarchy;
//
//		@Override
//		public void configure(HttpSecurity http) throws Exception {
//			http.authorizeRequests().anyRequest().authenticated();
//		}
//
//		@Override
//		public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
//			OAuth2WebSecurityExpressionHandler expressionHandler = new OAuth2WebSecurityExpressionHandler();
//			expressionHandler.setRoleHierarchy(this.roleHierarchy);
//			resources.expressionHandler(expressionHandler);
//		}
//
//	}
}
