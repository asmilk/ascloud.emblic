package ascloud.auth.ctrl;

import java.security.Principal;

import javax.servlet.ServletException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

	private static final Logger LOG = LoggerFactory.getLogger(ResourceController.class);

	@RequestMapping("/user_info")
	public Principal userInfo(Principal principal) {
		String name = principal.getClass().getName();
		LOG.info("name:{}", name);
		return principal;
	}
	
	@RequestMapping("/role/user")
	@PreAuthorize("hasRole('USER')")
	public boolean hasRoleUser(Principal principal) throws ServletException {
		LOG.info("principal:{}", principal);
		return true;
	}

	@RequestMapping("/role/admin")
	@PreAuthorize("hasRole('ADMIN')")
	public boolean hasRoleAdmin(Principal principal) throws ServletException {
		LOG.info("principal:{}", principal);
		return true;
	}

}
