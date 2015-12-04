import org.springframework.core.io.FileSystemResource

grails {
	plugin {
		springsecurity {

			controllerAnnotations.staticRules = [
				[pattern: '/',                 access: 'permitAll'],
				[pattern: '/error',            access: 'permitAll'],
				[pattern: '/index',            access: 'permitAll'],
				[pattern: '/index.gsp',        access: 'permitAll'],
				[pattern: '/shutdown',         access: 'permitAll'],
				[pattern: '/assets/**',        access: 'permitAll'],
				[pattern: '/**/js/**',         access: 'permitAll'],
				[pattern: '/**/css/**',        access: 'permitAll'],
				[pattern: '/**/images/**',     access: 'permitAll'],
				[pattern: '/**/favicon.ico',   access: 'permitAll']
			]

			debug.useFilter = true

			kerberos {
				client.debug = true
				debug = true
				ticketValidator {
					debug = true
					keyTabLocation = new FileSystemResource(new File(System.getProperty('serverKeytab.absolutePath')))
					servicePrincipal = 'HTTP/' + InetAddress.localHost.canonicalHostName + '@EXAMPLE.COM'
				}
			}
		}
	}
}
