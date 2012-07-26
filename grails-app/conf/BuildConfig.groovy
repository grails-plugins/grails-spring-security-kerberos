grails.project.work.dir = 'target'
grails.project.docs.output.dir = 'docs/manual' // for backwards-compatibility, the docs are checked into gh-pages branch
grails.project.source.level = 1.6

grails.project.dependency.resolution = {

	inherits 'global'
	log 'warn'

	repositories {
		grailsPlugins()
		grailsHome()
		grailsCentral()

		mavenRepo 'http://maven.springframework.org/milestone'
	}

	dependencies {
		compile('org.springframework.security.extensions:spring-security-kerberos-core:1.0.0.M2') {
			excludes 'junit', 'mockito-core', 'spring-security-core', 'spring-security-web',
			         'servlet-api', 'commons-logging'
		}
	}

	plugins {
		compile ':spring-security-core:1.2.7.3'

		build(':release:2.0.3', ':rest-client-builder:1.0.2') {
			export = false
		}
	}
}
