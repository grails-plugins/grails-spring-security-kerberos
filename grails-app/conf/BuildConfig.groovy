grails.project.class.dir = 'target/classes'
grails.project.test.class.dir = 'target/test-classes'
grails.project.test.reports.dir	= 'target/test-reports'
grails.project.docs.output.dir = 'docs' // for backwards-compatibility, the docs are checked into gh-pages branch

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
			transitive = false
		}
	}
}
