/* Copyright 2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package grails.plugin.springsecurity.kerberos

import grails.core.GrailsApplication
import grails.test.mixin.integration.Integration
import org.ietf.jgss.GSSContext
import org.ietf.jgss.GSSCredential
import org.ietf.jgss.GSSManager
import org.ietf.jgss.GSSName
import org.ietf.jgss.Oid
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.http.client.ClientHttpResponse
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.client.DefaultResponseErrorHandler
import org.springframework.web.client.RestTemplate
import spock.lang.Shared
import spock.lang.Specification

import javax.security.auth.Subject
import javax.security.auth.kerberos.KerberosPrincipal
import javax.security.auth.login.AppConfigurationEntry
import javax.security.auth.login.Configuration
import javax.security.auth.login.LoginContext
import java.security.PrivilegedAction

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@Integration
class KerberosAuthSpec extends Specification {

	private static final Oid KERB_V5_OID = new Oid('1.2.840.113554.1.2.2')
	private static final Oid KRB5_PRINCIPAL_NAME_OID = new Oid('1.2.840.113554.1.2.2.1')

	private @Shared GroovyMiniKdc kdc
	private @Shared File clientKeytab
	private @Shared String clientPrincipal
	private @Shared String serverPrincipal

	private RestTemplate restTemplate = new RestTemplate(new HttpComponentsClientHttpRequestFactory())

	GrailsApplication grailsApplication

	void setupSpec() {
		Properties conf = GroovyMiniKdc.createConf()
		conf[GroovyMiniKdc.DEBUG] = true
		kdc = new GroovyMiniKdc(conf, new File('build'))
		kdc.start()

		String host = InetAddress.localHost.canonicalHostName

		serverPrincipal = 'HTTP/' + host
		File serverKeytab = new File(kdc.workDir, 'server.keytab')
		kdc.createPrincipal serverKeytab, serverPrincipal
		System.setProperty 'serverKeytab.absolutePath', serverKeytab.absolutePath

		clientPrincipal = 'appuser'
		clientKeytab = new File(kdc.workDir, 'client.keytab')
		kdc.createPrincipal clientKeytab, clientPrincipal
	}

	void cleanupSpec() {
		kdc?.stop()
	}

	void testUnauthenticated() {
		given:
		HttpHeaders headers
		HttpStatus status
		restTemplate.errorHandler = new DefaultResponseErrorHandler() {
			void handleError(ClientHttpResponse clientResponse) throws IOException {
				headers = clientResponse.headers
				status = clientResponse.statusCode
			}
		}

		when:
		restTemplate.execute url, HttpMethod.GET, null, null

		then:
		status == HttpStatus.UNAUTHORIZED
		headers.getFirst(HttpHeaders.WWW_AUTHENTICATE) == 'Negotiate'
	}

	void testAuthenticated() {
		when:
		def headers = [(HttpHeaders.AUTHORIZATION): ['Negotiate ' + generateTicket()]]
		HttpEntity requestEntity = new HttpEntity(new LinkedMultiValueMap(headers))

		ResponseEntity<String> entity = restTemplate.exchange(url, HttpMethod.GET, requestEntity, String)

		then:
		entity.statusCode.value() == 200
		entity.body == 'Logged in with ROLE_ADMIN'
	}

	private String generateTicket() {

		Configuration loginConfig = new Configuration() {
			AppConfigurationEntry[] getAppConfigurationEntry(String name) {
				[new AppConfigurationEntry('com.sun.security.auth.module.Krb5LoginModule',
						AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
						[useKeyTab: 'true', keyTab: clientKeytab.absolutePath, principal: clientPrincipal,
						 storeKey: 'false', doNotPrompt: 'true', isInitiator: 'true'])] as AppConfigurationEntry[]
			}
		}

		Subject subject = new Subject(false, [new KerberosPrincipal(clientPrincipal)] as Set,
				Collections.emptySet(), Collections.emptySet())

		LoginContext lc = new LoginContext('', subject, null, loginConfig)
		lc.login()

		Subject.doAsPrivileged(lc.subject, new PrivilegedAction<String>() {
			String run() {
				GSSManager manager = GSSManager.instance
				GSSName clientName = manager.createName(clientPrincipal, KRB5_PRINCIPAL_NAME_OID)
				GSSCredential clientCred = manager.createCredential(clientName, 8 * 3600, KERB_V5_OID, GSSCredential.INITIATE_ONLY)
				GSSName serverName = manager.createName(serverPrincipal, KRB5_PRINCIPAL_NAME_OID)

				GSSContext context = manager.createContext(serverName, KERB_V5_OID, clientCred, GSSContext.DEFAULT_LIFETIME)
				context.requestMutualAuth true
				context.requestConf false
				context.requestInteg true

				byte[] outToken = context.initSecContext(new byte[0], 0, 0)
				context.dispose()

				outToken.encodeBase64()
			}
		}, null)
	}

	private String getUrl() {
		'http://localhost:' + grailsApplication.config.server.port + '/secure/admins'
	}
}
