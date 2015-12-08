grails.project.work.dir = 'target'
grails.project.docs.output.dir = 'docs/manual' // for backwards-compatibility, the docs are checked into gh-pages branch

grails.project.dependency.resolver = 'maven'
grails.project.dependency.resolution = {

	inherits 'global'
	log 'warn'

	repositories {
		grailsCentral()
		mavenLocal()
		mavenCentral()
	}

	dependencies {

		String springSecurityKerberosVersion = '1.0.1.RELEASE'
		compile "org.springframework.security.kerberos:spring-security-kerberos-core:$springSecurityKerberosVersion", {
			excludes 'spring-core', 'spring-security-core'
		}

		compile "org.springframework.security.kerberos:spring-security-kerberos-web:$springSecurityKerberosVersion", {
			excludes 'javax.servlet-api', 'spring-core', 'spring-security-kerberos-core', 'spring-security-web', 'spring-web'
		}
	}

	plugins {
		compile ':spring-security-core:2.0.0'

		build ':release:3.1.2', ':rest-client-builder:2.1.1', {
			export = false
		}
	}
}
