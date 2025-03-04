# SSO-POC

docker run -d --name keycloak \
-p 8080:8080 \
-e KEYCLOAK_ADMIN=admin \
-e KEYCLOAK_ADMIN_PASSWORD=admin \
quay.io/keycloak/keycloak:latest start-dev


2. Keycloak’ta SAML IdP Tanımlama
   Yeni Realm Oluşturun

"Create Realm" diyerek mirket-realm adında yeni bir realm oluşturun.
Client Tanımlayın

"Clients" sekmesine gidin ve Yeni Bir Client ekleyin.
Client ID: my-saml-app
Client Protocol: saml
Root URL: http://localhost:8081/login/saml2/sso/my-saml-idp
SAML Metadata XML’i Alın

"Clients" sekmesinde my-saml-app seçili haldeyken, "SAML Metadata XML" butonuna basarak metadata dosyasını alın.
