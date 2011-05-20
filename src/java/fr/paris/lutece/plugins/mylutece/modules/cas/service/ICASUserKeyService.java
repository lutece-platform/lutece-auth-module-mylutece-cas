package fr.paris.lutece.plugins.mylutece.modules.cas.service;

public interface ICASUserKeyService {

	/**
	 * return a string user key  
	 * @param objectKey the key object
	 * @return a string user key
	 */
	String getKey(Object objectKey);

}
