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

import groovy.transform.CompileStatic
import groovy.transform.TypeCheckingMode
import groovy.util.logging.Slf4j
import org.apache.commons.io.Charsets
import org.apache.commons.io.IOUtils
import org.apache.commons.lang.text.StrSubstitutor
import org.apache.directory.api.ldap.model.entry.DefaultEntry
import org.apache.directory.api.ldap.model.entry.Entry
import org.apache.directory.api.ldap.model.ldif.LdifEntry
import org.apache.directory.api.ldap.model.ldif.LdifReader
import org.apache.directory.api.ldap.model.name.Dn
import org.apache.directory.api.ldap.model.schema.SchemaManager
import org.apache.directory.api.ldap.schemaextractor.impl.DefaultSchemaLdifExtractor
import org.apache.directory.api.ldap.schemaloader.LdifSchemaLoader
import org.apache.directory.api.ldap.schemamanager.impl.DefaultSchemaManager
import org.apache.directory.server.constants.ServerDNConstants
import org.apache.directory.server.core.DefaultDirectoryService
import org.apache.directory.server.core.api.CacheService
import org.apache.directory.server.core.api.CoreSession
import org.apache.directory.server.core.api.DirectoryService
import org.apache.directory.server.core.api.InstanceLayout
import org.apache.directory.server.core.api.schema.SchemaPartition
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmIndex
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition
import org.apache.directory.server.core.partition.ldif.LdifPartition
import org.apache.directory.server.kerberos.kdc.KdcServer
import org.apache.directory.server.kerberos.shared.crypto.encryption.KerberosKeyFactory
import org.apache.directory.server.kerberos.shared.keytab.Keytab
import org.apache.directory.server.kerberos.shared.keytab.KeytabEntry
import org.apache.directory.server.protocol.shared.transport.TcpTransport
import org.apache.directory.server.protocol.shared.transport.UdpTransport
import org.apache.directory.shared.kerberos.KerberosTime

import java.text.MessageFormat

/**
 * Based on org.springframework.security.kerberos.test.MiniKdc
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@CompileStatic
@Slf4j
class GroovyMiniKdc {

	public static final String ORG_NAME = 'org.name'
	public static final String ORG_DOMAIN = 'org.domain'
	public static final String KDC_BIND_ADDRESS = 'kdc.bind.address'
	public static final String KDC_PORT = 'kdc.port'
	public static final String INSTANCE = 'instance'
	public static final String MAX_TICKET_LIFETIME = 'max.ticket.lifetime'
	public static final String MAX_RENEWABLE_LIFETIME = 'max.renewable.lifetime'
	public static final String TRANSPORT = 'transport'
	public static final String DEBUG = 'debug'

	private static final Set<String> PROPERTIES = [
		ORG_NAME, ORG_DOMAIN, KDC_BIND_ADDRESS, KDC_PORT, INSTANCE,
		MAX_TICKET_LIFETIME, MAX_RENEWABLE_LIFETIME, TRANSPORT, DEBUG] as Set

	static final Map<String, String> DEFAULT_CONFIG = [
		(KDC_BIND_ADDRESS): 'localhost',
		(KDC_PORT): '0',
		(INSTANCE): 'DefaultKrbServer',
		(ORG_NAME): 'EXAMPLE',
		(ORG_DOMAIN): 'COM',
		(TRANSPORT): 'TCP',
		(MAX_TICKET_LIFETIME): '86400000',
		(MAX_RENEWABLE_LIFETIME): '604800000',
		(DEBUG): 'false'].asImmutable()

	private Map<String, String> conf
	private DirectoryService ds
	private KdcServer kdc
	private int port
	private String realm
	private File workDir
	private File krb5conf

	static Map<String, String> createConf() {
		[:] + DEFAULT_CONFIG
	}

	GroovyMiniKdc(Map<String, String> conf, File workDir) {
		if (!conf.keySet().containsAll(PROPERTIES)) {
			throw new IllegalArgumentException("Missing configuration properties: ${PROPERTIES - conf.keySet()}")
		}

		this.workDir = new File(workDir, System.currentTimeMillis() as String)
		if (!workDir.exists() && !workDir.mkdirs()) {
			throw new RuntimeException("Cannot create directory $workDir")
		}

		log.info 'Configuration:'
		log.info '---------------------------------------------------------------'
		conf.each { key, value ->
			log.info '  {}: {}', key, value
		}
		log.info '  localhost hostname: {}', InetAddress.localHost.hostName
		log.info '  localhost canonical hostname: {}', InetAddress.localHost.canonicalHostName
		log.info '---------------------------------------------------------------'
		this.conf = conf
		port = conf[KDC_PORT] as int
		if (port == 0) {
			ServerSocket ss = new ServerSocket(0, 1, InetAddress.getByName(host))
			port = ss.localPort
			ss.close()
		}
		realm = orgName.toUpperCase() + '.' + orgDomain.toUpperCase()
	}

	int getPort() { port }
	String getHost() { conf[KDC_BIND_ADDRESS] }
	String getRealm() { realm }
	File getKrb5conf() { krb5conf }

	synchronized void start() {
		assert !kdc, 'Already started'
		initDirectoryService()
		initKDCServer()
	}

	private void initDirectoryService() {
		ds = new DefaultDirectoryService(instanceLayout: new InstanceLayout(workDir), cacheService: new CacheService())

		// first load the schema
		InstanceLayout instanceLayout = ds.instanceLayout
		File schemaPartitionDirectory = new File(instanceLayout.partitionsDirectory, 'schema')
		new DefaultSchemaLdifExtractor(instanceLayout.partitionsDirectory).extractOrCopy()

		SchemaManager schemaManager = new DefaultSchemaManager(new LdifSchemaLoader(schemaPartitionDirectory))
		schemaManager.loadAllEnabled()
		ds.schemaManager = schemaManager
		// Init the LdifPartition with schema
		LdifPartition schemaLdifPartition = new LdifPartition(schemaManager)
		schemaLdifPartition.partitionPath = schemaPartitionDirectory.toURI()

		// The schema partition
		SchemaPartition schemaPartition = new SchemaPartition(schemaManager)
		schemaPartition.wrappedPartition = schemaLdifPartition
		ds.schemaPartition = schemaPartition

		JdbmPartition systemPartition = new JdbmPartition(ds.schemaManager)
		systemPartition.id = 'system'
		systemPartition.partitionPath = new File(ds.instanceLayout.partitionsDirectory, systemPartition.id).toURI()
		systemPartition.suffixDn = new Dn(ServerDNConstants.SYSTEM_DN)
		systemPartition.schemaManager = ds.schemaManager
		ds.systemPartition = systemPartition

		ds.changeLog.enabled = false
		ds.denormalizeOpAttrsEnabled = true
		ds.addLast new KeyDerivationInterceptor()

		// create one partition
		JdbmPartition partition = new JdbmPartition(ds.schemaManager)
		partition.id = orgName
		partition.partitionPath = new File(ds.instanceLayout.partitionsDirectory, orgName).toURI()
		partition.suffixDn = new Dn('dc=' + orgName + ',dc=' + orgDomain)
		ds.addPartition partition
		// indexes
		partition.indexedAttributes = [new JdbmIndex('objectClass', false),
		                               new JdbmIndex('dc', false),
		                               new JdbmIndex('ou', false)] as Set

		// And start the ds
		ds.instanceId = conf[INSTANCE]
		ds.startup()

		// context entry, after ds.startup()
		Entry entry = ds.newEntry(new Dn('dc=' + orgName + ',dc=' + orgDomain))
		entry.add 'objectClass', 'top', 'domain'
		entry.add 'dc', orgName
		ds.adminSession.add entry
	}

	private void initKDCServer() {
		ClassLoader cl = Thread.currentThread().contextClassLoader
		InputStream stream = cl.getResourceAsStream('minikdc.ldiff')

		SchemaManager schemaManager = ds.schemaManager
		LdifReader reader
		try {
			reader = new LdifReader(new StringReader(StrSubstitutor.replace(stream.text, [
					'0': orgName.toLowerCase(),
					'1': orgDomain.toLowerCase(),
					'2': orgName.toUpperCase(),
					'3': orgDomain.toUpperCase(),
					'4': host])))
			reader.each { LdifEntry entry -> ds.adminSession.add new DefaultEntry(schemaManager, entry.getEntry()) }
		}
		finally {
			IOUtils.closeQuietly reader
			IOUtils.closeQuietly stream
		}

		kdc = new KdcServer(directoryService: ds)

		// transport
		String transport = conf[TRANSPORT]
		switch (transport.trim()) {
			case 'TCP': kdc.addTransports new TcpTransport(host, port, 3, 50); break
			case 'UDP': kdc.addTransports new UdpTransport(port); break
			default: throw new IllegalArgumentException("Invalid transport: $transport")
		}

		kdc.serviceName = conf[INSTANCE]
		kdc.config.maximumRenewableLifetime = conf[MAX_RENEWABLE_LIFETIME] as long
		kdc.config.maximumTicketLifetime = conf[MAX_TICKET_LIFETIME] as long
		kdc.config.paEncTimestampRequired = false
		kdc.start()

		StringBuilder sb = new StringBuilder()
		stream = cl.getResourceAsStream('minikdc-krb5.conf')
		try {
			stream.readLines(Charsets.UTF_8.name()).each { sb << it << '{3}' }
		}
		finally {
			IOUtils.closeQuietly stream
		}

		krb5conf = new File(workDir, 'krb5.conf').absoluteFile
		krb5conf.text = MessageFormat.format(sb.toString(), getRealm(), host, getPort() as String,
				System.getProperty('line.separator'))
		System.setProperty 'java.security.krb5.conf', krb5conf.absolutePath

		System.setProperty 'sun.security.krb5.debug', conf[DEBUG]

		refreshConfig()

		log.info 'MiniKdc listening at port: {}', getPort()
		log.info 'MiniKdc setting JVM krb5.conf to: {}', krb5conf.absolutePath
	}

	@CompileStatic(TypeCheckingMode.SKIP)
	private void refreshConfig() {
		Class<?> classRef = Class.forName(System.getProperty('java.vendor').contains('IBM') ?
				'com.ibm.security.krb5.internal.Config' : 'sun.security.krb5.Config')
		classRef."refresh"()
	}

	synchronized void stop() {
		if (kdc) {
			System.properties.remove 'java.security.krb5.conf'
			System.properties.remove 'sun.security.krb5.debug'
			kdc.stop()
			try {
				ds.shutdown()
			}
			catch (e) {
				log.error 'Could not shutdown ApacheDS properly: {}', e.message, e
			}
		}

		if (!workDir.deleteDir()) {
			log.warn "WARNING: cannot delete file $workDir.absolutePath"
		}
	}

	/**
	 * Creates a principal in the KDC with the specified user and password.
	 *
	 * @param principal principal name, do not include the domain.
	 * @param password password.
	 * @throws Exception thrown if the principal could not be created.
	 */
	synchronized void createPrincipal(String principal, String password) {
		String content = """\
dn: uid=$principal,ou=users,dc=$orgName,dc=$orgDomain
objectClass: top
objectClass: person
objectClass: inetOrgPerson
objectClass: krb5principal
objectClass: krb5kdcentry
cn: $principal
sn: $principal
uid: $principal
userPassword: $password
krb5PrincipalName: $principal@$realm
krb5KeyVersionNumber: 0"""

		CoreSession adminSession = ds.adminSession
		SchemaManager schemaManager = ds.schemaManager
		new LdifReader(new StringReader(content)).each { LdifEntry entry ->
			adminSession.add new DefaultEntry(schemaManager, entry.getEntry())
		}
	}

	/**
	 * Creates multiple principals in the KDC and adds them to a keytab file.
	 *
	 * @param keytabFile keytab file to add the created principals
	 * @param principals principals to add to the KDC, do not include the domain.
	 * @throws Exception thrown if the principals or the keytab file could not be created.
	 */
	void createPrincipal(File keytabFile, String... principals) {
		String generatedPassword = UUID.randomUUID().toString()
		principals.each { String principal ->
			createPrincipal principal, generatedPassword
			addToKeytabFile keytabFile, principal + '@' + getRealm(), generatedPassword
		}
	}

	/**
	 * Add the principal to the keytab file
	 * @param keytabFile the file
	 * @param principal the username in the form "username@realm"
	 * @param password the password
	 */
	static void addToKeytabFile(File keytabFile, String principal, String password) {
		KerberosTime timestamp = new KerberosTime()
		List<KeytabEntry> entries = KerberosKeyFactory.getKerberosKeys(principal, password).values().collect {
			new KeytabEntry(principal, 1, timestamp, it.keyVersion as byte, it)
		}
		new Keytab(entries: entries).write keytabFile
	}

	/**
	 * Creates a server keytab file. Returns the password in case it wasn't supplied and is needed when
	 * registering the principal in createPrincipal(String principal, String password). If the file exists
	 * it will append to it, potentially adding redundant entries.
	 * @param keytabFile the file
	 * @param realm the realm
	 * @return the password
	 */
	static String createServerKeytabFile(File keytabFile, String realm, String password = UUID.randomUUID().toString()) {
		addToKeytabFile keytabFile, 'HTTP/' + InetAddress.localHost.canonicalHostName + '@' + realm, password
		password
	}

	private String getOrgName() { conf[ORG_NAME] }
	private String getOrgDomain() { conf[ORG_DOMAIN] }
}
