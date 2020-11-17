FROM jboss/keycloak:4.8.3.Final
COPY ./esmocloak-ear/target/esmocloak-0.1-SNAPSHOT.ear /opt/jboss/keycloak/standalone/deployments/
COPY ./esmocloak-module/src/test/resources /resources
