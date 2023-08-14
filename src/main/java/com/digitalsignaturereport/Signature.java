package com.digitalsignaturereport;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Signature {
	
	private String originlFile;
	
	private String signature;
	
	private String publicKey;
	
	private String hash;
	
}
