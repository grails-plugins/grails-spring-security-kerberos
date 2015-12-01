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
security {
	kerberos {
		// activate kerberos plugin
		active = true

		client {
			debug = false
		}

		// Kerberos config file location can be specified here
		configLocation = null

		// enable debug logs for the kerberosConfig bean
		debug = false

		// skip SpnegoAuthenticationProcessingFilter processing if already authenticated
		skipIfAlreadyAuthenticated = true

		// Override with a url (e.g. '/login/auth') to forward there
		// in addition to setting the WWW-Authenticate header
		spnegoEntryPointForwardUrl = null

		successHandler {
			headerName = 'WWW-Authenticate'
			headerPrefix = 'Negotiate '
		}

		ticketValidator {
			debug = false
			holdOnToGSSContext = false
			keyTabLocation = null // must be set
			servicePrincipal = null // must be set
		}
	}
}
