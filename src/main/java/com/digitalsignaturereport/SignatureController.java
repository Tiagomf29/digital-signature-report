package com.digitalsignaturereport;

import java.io.IOException;
import java.security.GeneralSecurityException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;


@RestController
@RequestMapping("/signatures")
@CrossOrigin(origins = "*")
public class SignatureController {
		
	@PostMapping
	public Signature assinarDocumento(@RequestParam("originlFile") MultipartFile originlFile, 
									  @RequestParam("privatePassword") String privatePassword, 
									  @RequestParam("certificate") MultipartFile certificate) throws IOException, GeneralSecurityException {
	
		final String hash = DigestUtils.sha512Hex(originlFile.getBytes());
		
		final SignatureInterop signatureInterop = new SignatureInterop(certificate.getInputStream(), privatePassword);
		
		final byte[] signatureHash = signatureInterop.sign(hash);
		
		Signature signature = new Signature();
		signature.setOriginlFile(Base64.encodeBase64String(originlFile.getBytes()));
		signature.setSignature(Base64.encodeBase64String(signatureHash));
		signature.setPublicKey(Base64.encodeBase64String(signatureInterop.getPublicKey().getEncoded()));
		signature.setHash(hash);
		
		
		return signature;
	}

}
