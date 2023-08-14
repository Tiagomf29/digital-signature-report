package com.digitalsignaturereport;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignatureInterop {

	private final String algorithm	= "SHA256WithRSA";

	protected KeyStore ks;

	private String alias;

	private char[] ksPass;
	
	public SignatureInterop(final InputStream keystore, final String ks_pass) throws GeneralSecurityException, IOException
	{
		ksPass = ks_pass.toCharArray();
		ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(keystore, ksPass);
		alias = ks.aliases().nextElement();
	}
	
	public byte[] sign(final String message)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnrecoverableKeyException, KeyStoreException
		{
			final Signature signature = Signature.getInstance(algorithm);
			signature.initSign(getPrivateKey());
			signature.update(message.getBytes());
			return signature.sign();
		}
	
	public PrivateKey getPrivateKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException
	{
		return (PrivateKey) ks.getKey(alias, ksPass);
	}
	
	public boolean verify(final PublicKey publicKey, final String message, final byte[] signatureBytes)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException
		{
			final Signature signature = Signature.getInstance(algorithm);
			signature.initVerify(publicKey);
			signature.update(message.getBytes());
			return signature.verify(signatureBytes);
		}
	
	public X509Certificate getCertificate() throws KeyStoreException
	{
		return (X509Certificate) ks.getCertificate(alias);
	}

	public Key getPublicKey() throws GeneralSecurityException, IOException
	{
		return getCertificate().getPublicKey();
	}
	
}
