package com.poc.saml;

import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.BasicKeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;

public class IdPMetadataProvider {

    // Method to build the IdP metadata
    public EntityDescriptor buildIdPMetadata(String entityId, String ssoUrl, Credential signingCredential) {
        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        // Create EntityDescriptor
        EntityDescriptor entityDescriptor = (EntityDescriptor) builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME).buildObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        entityDescriptor.setEntityID(entityId);

        // Create IDPSSODescriptor
        IDPSSODescriptor idpSSODescriptor = (IDPSSODescriptor) builderFactory.getBuilder(IDPSSODescriptor.DEFAULT_ELEMENT_NAME).buildObject(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        idpSSODescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
        idpSSODescriptor.getKeyDescriptors().add(buildKeyDescriptor(signingCredential));
        idpSSODescriptor.getSingleSignOnServices().add(buildSSOService(ssoUrl));

        // Add IDPSSODescriptor to EntityDescriptor
        entityDescriptor.getRoleDescriptors().add(idpSSODescriptor);

        return entityDescriptor;
    }

    // Method to build KeyDescriptor
    private KeyDescriptor buildKeyDescriptor(Credential credential) {
        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        // Create KeyDescriptor
        KeyDescriptor keyDescriptor = (KeyDescriptor) builderFactory.getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME).buildObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
        keyDescriptor.setUse(UsageType.SIGNING);

        // Generate KeyInfo using the credential
        BasicKeyInfoGeneratorFactory keyInfoGeneratorFactory = new BasicKeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitPublicKeyValue(true); // Adjust settings based on your requirements
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

        try {
            KeyInfo keyInfo = keyInfoGenerator.generate(credential);
            keyDescriptor.setKeyInfo(keyInfo);
        } catch (Exception e) {
            throw new RuntimeException("Error generating KeyInfo", e);
        }

        return keyDescriptor;
    }


    // Method to build SingleSignOnService
    private SingleSignOnService buildSSOService(String ssoUrl) {
        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        SingleSignOnService ssoService = (SingleSignOnService) builderFactory.getBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME).buildObject(SingleSignOnService.DEFAULT_ELEMENT_NAME);
        ssoService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        ssoService.setLocation(ssoUrl);

        return ssoService;
    }
}
