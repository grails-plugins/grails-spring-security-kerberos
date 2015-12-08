/* Copyright 2011-2015 the original author or authors.
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
import grails.plugin.springsecurity.SecurityFilterPosition
import grails.plugin.springsecurity.SpringSecurityUtils

import org.springframework.security.kerberos.authentication.KerberosAuthenticationProvider
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider
import org.springframework.security.kerberos.authentication.sun.GlobalSunJaasKerberosConfig
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosClient
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator
import org.springframework.security.kerberos.web.authentication.ResponseHeaderSettingKerberosAuthenticationSuccessHandler
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter
import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint

class SpringSecurityKerberosGrailsPlugin {

	String version = '1.0.0'
	String grailsVersion = '2.3 > *'
	List loadAfter = ['springSecurityCore']
	List pluginExcludes = [
		'docs/**',
		'src/docs/**'
	]

	String author = 'Burt Beckwith'
	String authorEmail = 'burt@burtbeckwith.com'
	String title = 'Spring Security Kerberos Plugin'
	String description = 'Spring Security Kerberos plugin'
	String documentation = 'http://grails-plugins.github.io/grails-spring-security-kerberos/'

	String license = 'APACHE'
	def organization = [name: 'Grails', url: 'http://www.grails.org/']
	def issueManagement = [url: 'https://github.com/grails-plugins/grails-spring-security-kerberos/issues']
	def scm = [url: 'https://github.com/grails-plugins/grails-spring-security-kerberos']

	def doWithSpring = {
		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) {
			return
		}

		SpringSecurityUtils.loadSecondaryConfig 'DefaultKerberosSecurityConfig'

		// have to reload again after overlaying DefaultKerberosSecurityConfig
		conf = SpringSecurityUtils.securityConfig

		if (!conf.kerberos.active) {
			return
		}

		boolean printStatusMessages = (conf.printStatusMessages instanceof Boolean) ? conf.printStatusMessages : true

		if (printStatusMessages) {
			println '\nConfiguring Spring Security Kerberos ...'
		}

		SpringSecurityUtils.registerProvider 'kerberosAuthenticationProvider'
		SpringSecurityUtils.registerProvider 'kerberosServiceAuthenticationProvider'
		SpringSecurityUtils.registerFilter 'spnegoAuthenticationProcessingFilter', SecurityFilterPosition.BASIC_AUTH_FILTER

		authenticationEntryPoint(SpnegoEntryPoint, conf.kerberos.spnegoEntryPointForwardUrl ?: null)

		authenticationSuccessHandler(ResponseHeaderSettingKerberosAuthenticationSuccessHandler) {
			headerName = conf.kerberos.successHandler.headerName // 'WWW-Authenticate'
			headerPrefix = conf.kerberos.successHandler.headerPrefix // 'Negotiate '
		}

		spnegoAuthenticationProcessingFilter(SpnegoAuthenticationProcessingFilter) {
			authenticationDetailsSource = ref('authenticationDetailsSource')
			authenticationManager = ref('authenticationManager')
			sessionAuthenticationStrategy = ref('sessionAuthenticationStrategy')
			skipIfAlreadyAuthenticated = conf.kerberos.skipIfAlreadyAuthenticated // true
			successHandler = ref('authenticationSuccessHandler')
			// failureHandler = ref('authenticationFailureHandler')
		}

		kerberosTicketValidator(SunJaasKerberosTicketValidator) {
			debug = conf.kerberos.ticketValidator.debug // false
			holdOnToGSSContext = conf.kerberos.ticketValidator.holdOnToGSSContext // false
			keyTabLocation = conf.kerberos.ticketValidator.keyTabLocation
			servicePrincipal = conf.kerberos.ticketValidator.servicePrincipal
		}

		kerberosAuthenticationProvider(KerberosAuthenticationProvider) {
			kerberosClient = ref('kerberosClient')
			userDetailsService = ref('userDetailsService')
		}

		kerberosClient(SunJaasKerberosClient) {
			debug = conf.kerberos.client.debug // false
		}

		kerberosServiceAuthenticationProvider(KerberosServiceAuthenticationProvider) {
			ticketValidator = ref('kerberosTicketValidator')
			userDetailsService = ref('userDetailsService')
		}

		kerberosConfig(GlobalSunJaasKerberosConfig) {
			debug = conf.kerberos.debug // false
			krbConfLocation = conf.kerberos.configLocation // null
		}

		if (printStatusMessages) {
			println '... finished configuring Spring Security Kerberos\n'
		}
	}
}
