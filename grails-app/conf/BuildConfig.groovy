grails.project.work.dir = 'target'
grails.project.docs.output.dir = 'docs/manual' // for backwards-compatibility, the docs are checked into gh-pages branch

grails.project.dependency.resolution = {

	inherits 'global'
	log 'warn'

	repositories {
		grailsPlugins()
		grailsHome()
		grailsCentral()

		mavenRepo 'http://repo.spring.io/milestone'
	}

	dependencies {
		compile('org.springframework.security.extensions:spring-security-kerberos-core:1.0.0.M2') {
			excludes 'junit', 'mockito-core', 'spring-security-core', 'spring-security-web',
			         'servlet-api', 'commons-logging'
		}
	}

	plugins {
		compile ':spring-security-core:2.0-RC2'

		build ':release:2.2.1', ':rest-client-builder:1.0.3', {
			export = false
		}
	}
}
