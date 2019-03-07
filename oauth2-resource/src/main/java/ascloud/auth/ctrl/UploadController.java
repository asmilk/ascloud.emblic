package ascloud.auth.ctrl;

import java.io.IOException;

import javax.servlet.http.Part;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class UploadController {

	private static final Logger LOG = LoggerFactory.getLogger(UploadController.class);

	@PostMapping("/upload")
	public String upload(@RequestParam("name") String name, @RequestParam("file") Part part) throws IOException {
		LOG.info("name:{}", name);

		String contentType = part.getContentType();
		String submittedFileName = part.getSubmittedFileName();

		LOG.info("contentType:{}", contentType);
		LOG.info("submittedFileName:{}", submittedFileName);

		String fileName = System.currentTimeMillis() + "_" + submittedFileName;
		LOG.info("fileName:{}", fileName);

		String filePath = "D:\\dev\\ws\\sts4\\asmilk\\ascloud.emblic\\oauth2-resource\\src\\main\\resources\\static\\upload\\";

		part.write(filePath + fileName);
		return "redirect:/api/resc/upload/" + fileName;
	}

}
