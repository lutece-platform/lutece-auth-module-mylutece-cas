package fr.paris.lutece.plugins.mylutece.modules.cas.service;

public class DefaultCASUserKeyService implements ICASUserKeyService {

	/*
	 * (non-Javadoc)
	 * @see fr.paris.lutece.plugins.mylutece.modules.cas.service.ICASUserKeyService#getKey(java.lang.Object)
	 */
	public String getKey(Object objectKey) {
		return (String) objectKey;
	}

}
