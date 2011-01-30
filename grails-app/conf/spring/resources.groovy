import org.codehaus.groovy.grails.plugins.springsecurity.kerberos.NoopTicketValidator

beans = {
	kerberosTicketValidator(NoopTicketValidator)
}
