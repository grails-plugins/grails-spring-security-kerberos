/* Copyright 2011 the original author or authors.
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
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityFilterPosition
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

import org.springframework.security.extensions.kerberos.GlobalSunJaasKerberosConfig
import org.springframework.security.extensions.kerberos.KerberosServiceAuthenticationProvider
import org.springframework.security.extensions.kerberos.SunJaasKerberosTicketValidator
import org.springframework.security.extensions.kerberos.web.SpnegoAuthenticationProcessingFilter
import org.springframework.security.extensions.kerberos.web.SpnegoEntryPoint

class SpringSecurityKerberosGrailsPlugin {

	String version = '0.1'
	String grailsVersion = '1.2.2 > *'
	Map dependsOn = ['springSecurityCore': '1.0 > *']
	List pluginExcludes = [
		'docs/**',
		'src/docs/**'
	]

	String author = 'Burt Beckwith'
	String authorEmail = 'beckwithb@vmware.com'
	String title = 'Spring Security Kerberos Plugin'
	String description = 'Spring Security Kerberos plugin'
	String documentation = 'http://grails.org/plugin/spring-security-kerberos'

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
        
		println 'Configuring Spring Security Kerberos ...'
		SpringSecurityUtils.registerProvider 'kerberosServiceAuthenticationProvider'
		SpringSecurityUtils.registerFilter 'spnegoAuthenticationProcessingFilter',
				SecurityFilterPosition.BASIC_AUTH_FILTER

		authenticationEntryPoint(SpnegoEntryPoint)

		spnegoAuthenticationProcessingFilter(SpnegoAuthenticationProcessingFilter) {
			authenticationManager = ref('authenticationManager')
//			successHandler = ref('authenticationSuccessHandler')
//			failureHandler = ref('authenticationFailureHandler')
		}

		kerberosTicketValidator(SunJaasKerberosTicketValidator) {
			servicePrincipal = conf.kerberos.ticketValidator.servicePrincipal
			keyTabLocation = conf.kerberos.ticketValidator.keyTabLocation
			debug = conf.kerberos.ticketValidator.debug // false
		}

		kerberosServiceAuthenticationProvider(KerberosServiceAuthenticationProvider) {
			userDetailsService = ref('userDetailsService')
			ticketValidator = ref('kerberosTicketValidator')
		}

		kerberosConfig(GlobalSunJaasKerberosConfig) {
			debug = conf.kerberos.debug // false
			krbConfLocation = conf.kerberos.configLocation // null
		}
	}
}
