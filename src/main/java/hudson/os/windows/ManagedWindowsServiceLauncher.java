/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.os.windows;

import com.cloudbees.plugins.credentials.*;
import com.cloudbees.plugins.credentials.common.StandardUsernameListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.domains.HostnameRequirement;
import com.cloudbees.plugins.credentials.domains.SchemeRequirement;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import com.google.common.annotations.VisibleForTesting;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.*;
import hudson.model.*;
import hudson.os.windows.ManagedWindowsServiceAccount.AnotherUser;
import hudson.os.windows.ManagedWindowsServiceAccount.LocalSystem;
import hudson.remoting.Channel;
import hudson.remoting.Channel.Listener;
import hudson.remoting.SocketInputStream;
import hudson.remoting.SocketOutputStream;
import hudson.security.ACL;
import hudson.security.AccessControlled;
import hudson.slaves.*;
import hudson.tools.JDKInstaller;
import hudson.tools.JDKInstaller.CPU;
import hudson.tools.JDKInstaller.Platform;
import hudson.util.DescribableList;
import hudson.util.IOUtils;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import hudson.util.jna.DotNet;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jenkins.model.Jenkins;
import org.acegisecurity.context.SecurityContext;
import org.acegisecurity.context.SecurityContextHolder;
import org.apache.commons.lang.StringUtils;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.io.SAXReader;
import org.jinterop.dcom.common.JIDefaultAuthInfoImpl;
import org.jinterop.dcom.common.JIException;
import org.jinterop.dcom.core.JISession;
import org.jvnet.hudson.remcom.WindowsRemoteProcessLauncher;
import org.jvnet.hudson.wmi.SWbemServices;
import org.jvnet.hudson.wmi.WMI;
import org.jvnet.hudson.wmi.Win32Service;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import java.io.*;
import java.net.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.cloudbees.plugins.credentials.CredentialsMatchers.allOf;
import static com.cloudbees.plugins.credentials.CredentialsMatchers.withUsername;
import static hudson.Util.copyStreamAndClose;
import static org.jvnet.hudson.wmi.Win32Service.Win32OwnProcess;

/**
 * Windows slave installed/managed as a service entirely remotely
 *
 * @author Kohsuke Kawaguchi
 */
public class ManagedWindowsServiceLauncher extends ComputerLauncher {

    public static final SchemeRequirement WINDOWS_SCHEME = new SchemeRequirement("windows");

    /**
     * "[DOMAIN\\]USERNAME" to follow the Windows convention.
     */
    @Deprecated
    public final transient String userName;

    @Deprecated
    public final transient Secret password;

    /**
     * The id of the credentials to use
     */
    @CheckForNull
    private String credentialsId;

    /**
     * Transient stash of the credentials to use, mostly just for providing floating user object.
     */
    @CheckForNull
    private transient StandardUsernamePasswordCredentials credentials;
    
    public final String vmargs;

    public final String javaPath;

    /**
     * @deprecated Use {@link #account}
     */
    public transient final AccountInfo logOn;

    /**
     * Specifies the account used to run the service.
     */
    private ManagedWindowsServiceAccount account;
    
    public static class AccountInfo extends AbstractDescribableImpl<AccountInfo> {
        @Deprecated
        public final transient String userName;
        @Deprecated
        public final transient Secret password;

        public String credentialsId;

        private transient StandardUsernamePasswordCredentials credentials;

        @DataBoundConstructor
        public AccountInfo(StandardUsernamePasswordCredentials credentials) {
            this.credentials = credentials;
            this.credentialsId = credentials == null ? null : credentials.getId();
            this.userName = null;
            this.password = null;
        }

        /**
         * @param userName The username to connect as.
         * @param password The password to connect with.
         * @deprecated Use the {@link StandardUsernamePasswordCredentials} based version.
         */
        @Deprecated
        public AccountInfo(String userName, String password) {
            this(upgrade(userName, Secret.fromString(password), null));
        }

        public StandardUsernamePasswordCredentials getCredentials() {
            this.credentials = lookupCredentials(this.credentials, this.credentialsId, this.userName, this.password, null);
            this.credentialsId = this.credentials == null ? null : this.credentials.getId();
            return credentials;
        }

        @Extension
        public static class DescriptorImpl extends Descriptor<AccountInfo> {
            @Override
            public String getDisplayName() {
                return ""; // unused
            }
        }
    }

    /**
     * Host name to connect to. For compatibility reasons, null if the same with the slave name.
     * @since 1.419
     */
    public final String host;

    /**
     * @see ManagedWindowsServiceLauncher#ManagedWindowsServiceLauncher(StandardUsernamePasswordCredentials, String, ManagedWindowsServiceAccount, String, String)
     */
    @Deprecated
    public ManagedWindowsServiceLauncher(String userName, String password) {
        this (userName, password, null);
    }

    /**
     * @see ManagedWindowsServiceLauncher#ManagedWindowsServiceLauncher(StandardUsernamePasswordCredentials, String, ManagedWindowsServiceAccount, String, String)
     */
    @Deprecated
    public ManagedWindowsServiceLauncher(String userName, String password, String host) {
        this(userName, password, host, null, null);
    }

    /**
     * @see ManagedWindowsServiceLauncher#ManagedWindowsServiceLauncher(StandardUsernamePasswordCredentials, String, ManagedWindowsServiceAccount, String, String)
     */
    @Deprecated
    public ManagedWindowsServiceLauncher(String userName, String password, String host, AccountInfo account) {
        this(userName,password,host,account==null ? new LocalSystem() : new AnotherUser(account.userName,account.password), null);
    }

    /**
     * @see ManagedWindowsServiceLauncher#ManagedWindowsServiceLauncher(StandardUsernamePasswordCredentials, String, ManagedWindowsServiceAccount, String, String)
     */
    @Deprecated
    public ManagedWindowsServiceLauncher(String userName, String password, String host, ManagedWindowsServiceAccount account, String vmargs) {
        this(userName, password, host, account, vmargs, "");
    }

    /**
     * Constructor ManagedWindowsServiceLauncher creates a new ManagedWindowsServiceLauncher instance.
     *
     * @param userName The username to connect as.
     * @param password The password to connect with.
     * @param host The host to connect to
     * @param account The account to use to control the service
     * @param vmargs The arguments passed to the VM when starting it.
     * @param javaPath Path to the host jdk installation. If <code>null</code> the jdk will be auto detected or installed by the {@link JDKInstaller}
     * @deprecated use the {@link StandardUsernamePasswordCredentials} based version
     */
    @Deprecated
    public ManagedWindowsServiceLauncher(String userName, String password, String host, ManagedWindowsServiceAccount account, String vmargs, String javaPath) {
        this(upgrade(userName, Secret.fromString(password), Util.fixEmptyAndTrim(host)), host, account, vmargs, javaPath);
    }

    @DataBoundConstructor
    public ManagedWindowsServiceLauncher(String credentialsId, String host, ManagedWindowsServiceAccount account, String vmargs, String javaPath) {
        this(lookupSystemCredentials(credentialsId), host, account, vmargs, javaPath);
    }

    /**
     * Constructor ManagedWindowsServiceLauncher creates a new ManagedWindowsServiceLauncher instance.
     * @param credentials The credentials to connect as
     * @param host The host to connect to
     * @param account The account to use to control the service
     * @param vmargs The arguments passed to the VM when starting it.
     * @param javaPath Path to the host jdk installation. If <code>null</code> the jdk will be auto detected or installed by the {@link JDKInstaller}
     */
    public ManagedWindowsServiceLauncher(StandardUsernamePasswordCredentials credentials, String host, ManagedWindowsServiceAccount account, String vmargs, String javaPath) {
        this.userName = null;
        this.password = null;
        this.credentials = credentials;
        this.credentialsId = credentials == null ? null : credentials.getId();
        this.vmargs = Util.fixEmptyAndTrim(vmargs);
        this.javaPath = Util.fixEmptyAndTrim(javaPath);
        this.host = Util.fixEmptyAndTrim(host);
        this.account = account==null ? new LocalSystem() : account;
        this.logOn = null;
    }

    public Object readResolve() {
        if (logOn!=null)
            account = new AnotherUser(logOn.userName,logOn.password);
        return this;
    }

    public @CheckForNull String getCredentialsId() {
        if (credentialsId == null && (userName != null || password != null)) {
            initCredentials();
        }
        return this.credentialsId;
    }

    public @CheckForNull StandardUsernamePasswordCredentials getCredentials() {
        initCredentials();
        return this.credentials;
    }

    private void initCredentials() {
        this.credentials = lookupCredentials(this.credentials, this.credentialsId, this.userName, this.password, this.host);
        this.credentialsId = this.credentials == null ? null : this.credentials.getId();
    }

    private JIDefaultAuthInfoImpl createAuth() throws IOException {
        StandardUsernamePasswordCredentials credentials = getCredentials();
        if (credentials == null) {
            throw new AbortException("No credentials could be resolved. Please check the node configuration.");
        }
        String userName = credentials.getUsername();
        String password = Secret.toString(credentials.getPassword());
        String[] tokens = userName.split("\\\\");
        if(tokens.length==2)
            return new JIDefaultAuthInfoImpl(tokens[0], tokens[1], password);
        return new JIDefaultAuthInfoImpl("", userName, password);
    }

    private NtlmPasswordAuthentication createSmbAuth() throws IOException {
        JIDefaultAuthInfoImpl auth = createAuth();
        return new NtlmPasswordAuthentication(auth.getDomain(), auth.getUserName(), auth.getPassword());
    }

    public ManagedWindowsServiceAccount getAccount() {
        return account;
    }

    private AccountInfo getLogOn() {
        if (account==null)  return null;
        return account.getAccount(this);
    }

    @Override
    public void launch(final SlaveComputer computer, final TaskListener listener) throws IOException, InterruptedException {
        try {
            final PrintStream logger = listener.getLogger();
            final String name = determineHost(computer);

            logger.println(Messages.ManagedWindowsServiceLauncher_ConnectingTo(getTimestamp(), name));

            InetAddress host = InetAddress.getByName(name);

            /*
                Somehow this didn't work for me, so I'm disabling it.
             */
            // ping check
//            if (!host.isReachable(3000)) {
//                logger.println("Failed to ping "+name+". Is this a valid reachable host name?");
//                // continue anyway, just in case it's just ICMP that's getting filtered
//            }

            checkPort135Access(logger, name, host);

            JIDefaultAuthInfoImpl auth = createAuth();
            JISession session = JISession.createSession(auth);
            session.setGlobalSocketTimeout(60000);
            SWbemServices services = WMI.connect(session, name);


            String path = computer.getNode().getRemoteFS();
            if (path.indexOf(':')==-1)   throw new IOException("Remote file system root path of the slave needs to be absolute: "+path);
            SmbFile remoteRoot = new SmbFile("smb://" + name + "/" + path.replace('\\', '/').replace(':', '$')+"/",createSmbAuth());

            if(!remoteRoot.exists())
                remoteRoot.mkdirs();

            String java = resolveJava(computer);

            try {// does Java exist?
                logger.println("Checking if Java exists");
                WindowsRemoteProcessLauncher wrpl = new WindowsRemoteProcessLauncher(name,auth);
                Process proc = wrpl.launch("\"" +java + "\" -version","c:\\");
                proc.getOutputStream().close();
                StringWriter console = new StringWriter();
                IOUtils.copy(proc.getInputStream(), console);
                proc.getInputStream().close();
                int exitCode = proc.waitFor();
                if (exitCode==1) {// we'll get this error code if Java is not found
                    logger.println("No Java found. Downloading JDK");
                    JDKInstaller jdki = new JDKInstaller("jdk-6u16-oth-JPR@CDS-CDS_Developer",true);
                    URL jdk = jdki.locate(listener, Platform.WINDOWS, CPU.i386);

                    listener.getLogger().println("Installing JDK");
                    copyStreamAndClose(jdk.openStream(), new SmbFile(remoteRoot, "jdk.exe").getOutputStream());

                    String javaDir = path + "\\jdk"; // this is where we install Java to

                    WindowsRemoteFileSystem fs = new WindowsRemoteFileSystem(name, createSmbAuth());
                    fs.mkdirs(javaDir);

                    jdki.install(new WindowsRemoteLauncher(listener,wrpl), Platform.WINDOWS,
                            fs, listener, javaDir ,path+"\\jdk.exe");
                } else {
                    checkJavaVersion(logger, java, new BufferedReader(new StringReader(console.toString())));
                }
            } catch (Exception e) {
                e.printStackTrace(listener.error("Failed to prepare Java"));
                return;
            }

// this just doesn't work --- trying to obtain the type or check the existence of smb://server/C$/ results in "access denied"    
//            {// check if the administrative share exists
//                String fullpath = remoteRoot.getPath();
//                int idx = fullpath.indexOf("$/");
//                if (idx>=0) {// this must be true but be defensive since all we are trying to do here is a friendlier error check
//                    boolean exists;
//                    try {
//                        // SmbFile.exists() doesn't work on a share
//                        new SmbFile(fullpath.substring(0, idx + 2)).getType();
//                        exists = true;
//                    } catch (SmbException e) {
//                        // on Windows XP that I was using for the test, if the share doesn't exist I get this error
//                        // a thread in jcifs library ML confirms this, too:
//                        // http://old.nabble.com/"The-network-name-cannot-be-found"-after-30-seconds-td18859163.html
//                        if (e.getNtStatus()== NtStatus.NT_STATUS_BAD_NETWORK_NAME)
//                            exists = false;
//                        else
//                            throw e;
//                    }
//                    if (!exists) {
//                        logger.println(name +" appears to be missing the administrative share "+fullpath.substring(idx-1,idx+1)/*C$*/);
//                        return;
//                    }
//                }
//            }

            String id = generateServiceId(path);
            Win32Service slaveService = services.getService(id);
            if(slaveService==null) {
                logger.println(Messages.ManagedWindowsServiceLauncher_InstallingSlaveService(getTimestamp()));
                if(!DotNet.isInstalled(2,0, name, auth)) {
                    // abort the launch
                    logger.println(Messages.ManagedWindowsServiceLauncher_DotNetRequired(getTimestamp()));
                    return;
                }

                // copy exe
                logger.println(Messages.ManagedWindowsServiceLauncher_CopyingSlaveExe(getTimestamp()));
                copyStreamAndClose(getClass().getResource("/windows-service/jenkins.exe").openStream(), new SmbFile(remoteRoot,"jenkins-slave.exe").getOutputStream());

                copyStreamAndClose(getClass().getResource("/windows-service/jenkins.exe.config").openStream(), new SmbFile(remoteRoot,"jenkins-slave.exe.config").getOutputStream());

                copySlaveJar(logger, remoteRoot);

                // copy jenkins-slave.xml
                String xml = createAndCopyJenkinsSlaveXml(java, id, logger, remoteRoot);

                // install it as a service
                logger.println(Messages.ManagedWindowsServiceLauncher_RegisteringService(getTimestamp()));
                Document dom = new SAXReader().read(new StringReader(xml));
                Win32Service svc = services.Get("Win32_Service").cast(Win32Service.class);
                int r;
                AccountInfo logOn = getLogOn();
                if (logOn == null) {
                    r = svc.Create(
                        id,
                        dom.selectSingleNode("/service/name").getText()+" at "+path,
                        path+"\\jenkins-slave.exe",
                        Win32OwnProcess, 0, "Manual", true);
                } else {
                    StandardUsernamePasswordCredentials logOnCredentials = logOn.getCredentials();
                    r = svc.Create(
                        id,
                        dom.selectSingleNode("/service/name").getText()+" at "+path,
                        path+"\\jenkins-slave.exe",
                        Win32OwnProcess,
                        0,
                        "Manual",
                        false, // When using a different user, it isn't possible to interact
                        logOnCredentials.getUsername(),
                        Secret.toString(logOnCredentials.getPassword()),
                        null, null, null);

                }
                if(r!=0) {
                    listener.error("Failed to create a service: "+svc.getErrorMessage(r));
                    return;
                }
                slaveService = services.getService(id);
            } else {
                createAndCopyJenkinsSlaveXml(java, id, logger, remoteRoot);
                copySlaveJar(logger, remoteRoot);
            }

            logger.println(Messages.ManagedWindowsServiceLauncher_StartingService(getTimestamp()));
            slaveService.start();

            // wait until we see the port.txt, but don't do so forever
            logger.println(Messages.ManagedWindowsServiceLauncher_WaitingForService(getTimestamp()));
            SmbFile portFile = new SmbFile(remoteRoot, "port.txt");
            for( int i=0; !portFile.exists(); i++ ) {
                if(i>=30) {
                    listener.error(Messages.ManagedWindowsServiceLauncher_ServiceDidntRespond(getTimestamp()));
                    return;
                }
                Thread.sleep(1000);
            }
            int p = readSmbFile(portFile);

            // connect
            logger.println(Messages.ManagedWindowsServiceLauncher_ConnectingToPort(getTimestamp(),p));
            final Socket s = new Socket(name,p);

            // ready
            computer.setChannel(new BufferedInputStream(new SocketInputStream(s)),
                new BufferedOutputStream(new SocketOutputStream(s)),
                listener.getLogger(),new Listener() {
                    @Override
                    public void onClosed(Channel channel, IOException cause) {
                        afterDisconnect(computer,listener);
                    }
                });
            //destroy session to free the socket	
            JISession.destroySession(session);
        } catch (UnknownHostException e) {
            listener.error(Messages.ManagedWindowsServiceLauncher_UnknownHost(getTimestamp(), e.getMessage()));
        } catch (SmbException e) {
            e.printStackTrace(listener.error(e.getMessage()));
        } catch (JIException e) {
            if(e.getErrorCode()==5)
                // access denied error
                e.printStackTrace(listener.error(Messages.ManagedWindowsServiceLauncher_AccessDenied(getTimestamp())));
            else
                e.printStackTrace(listener.error(e.getMessage()));
        } catch (DocumentException e) {
            e.printStackTrace(listener.error(e.getMessage()));
        }
    }

    private String resolveJava(SlaveComputer computer) {
        if (StringUtils.isNotBlank(javaPath)) {
            return getEnvVars(computer).expand(javaPath);
        }
        return "java";
    }

    // -- duplicates code from ssh-slaves-plugin
    private EnvVars getEnvVars(SlaveComputer computer) {
        final EnvVars global = getEnvVars(Jenkins.getInstance());

        final EnvVars local = getEnvVars(computer.getNode());

        if (global != null) {
            if (local != null) {
                final EnvVars merged = new EnvVars(global);
                merged.overrideAll(local);

                return merged;
            } else {
                return global;
            }
        } else if (local != null) {
            return local;
        } else {
            return new EnvVars();
        }
    }

    private EnvVars getEnvVars(Node n) {
        return getEnvVars(n.getNodeProperties());
    }

    private EnvVars getEnvVars(DescribableList<NodeProperty<?>, NodePropertyDescriptor> dl) {
        final EnvironmentVariablesNodeProperty evnp = dl.get(EnvironmentVariablesNodeProperty.class);
        if (evnp == null) {
            return null;
        }
        return evnp.getEnvVars();
    }


    private void checkPort135Access(PrintStream logger, String name, InetAddress host) throws IOException {
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress(host,135),5000);
        } catch (IOException e) {
            logger.println("Failed to connect to port 135 of "+name+". Is Windows firewall blocking this port? Or did you disable DCOM service?");
            // again, let it continue.
        } finally {
            s.close();
        }
    }

    /**
     * Determines the host name (or the IP address) to connect to.
     */
    protected String determineHost(Computer c) {
        // If host not provided, default to the slave name
        if (StringUtils.isBlank(host)) {
            return c.getName();
        } else {
            return host;
        }
    }
    
    private String createAndCopyJenkinsSlaveXml(String java, String serviceId, PrintStream logger, SmbFile remoteRoot) throws IOException {
        logger.println(Messages.ManagedWindowsServiceLauncher_CopyingSlaveXml(getTimestamp()));
        String xml = generateSlaveXml(serviceId,
                java + "w.exe", vmargs, "-tcp %BASE%\\port.txt");
        copyStreamAndClose(new ByteArrayInputStream(xml.getBytes("UTF-8")), new SmbFile(remoteRoot,"jenkins-slave.xml").getOutputStream());
        return xml;
    }

    private void copySlaveJar(PrintStream logger, SmbFile remoteRoot) throws IOException {
        // copy slave.jar
        logger.println(Messages.ManagedWindowsServiceLauncher_CopyingSlaveJar(getTimestamp()));
        copyStreamAndClose(Jenkins.getInstance().getJnlpJars("slave.jar").getURL().openStream(), new SmbFile(remoteRoot,"slave.jar").getOutputStream());
    }

    private int readSmbFile(SmbFile f) throws IOException {
        InputStream in=null;
        try {
            in = f.getInputStream();
            return Integer.parseInt(IOUtils.toString(in));
        } finally {
            IOUtils.closeQuietly(in);
        }
    }

    @Override
    public void afterDisconnect(SlaveComputer computer, TaskListener listener) {
        try {
            JIDefaultAuthInfoImpl auth = createAuth();
            JISession session = JISession.createSession(auth);
            session.setGlobalSocketTimeout(60000);
            SWbemServices services = WMI.connect(session, determineHost(computer));
            String id = generateServiceId(computer.getNode().getRemoteFS());
            Win32Service slaveService = services.getService(id);
            if(slaveService!=null) {
                listener.getLogger().println(Messages.ManagedWindowsServiceLauncher_StoppingService(getTimestamp()));
                slaveService.StopService();
                listener.getLogger().println(Messages.ManagedWindowsServiceLauncher_UnregisteringService(getTimestamp()));
                slaveService.Delete();
            }
            //destroy session to free the socket	
            JISession.destroySession(session);
        } catch (UnknownHostException e) {
            e.printStackTrace(listener.error(e.getMessage()));
        } catch (JIException e) {
            e.printStackTrace(listener.error(e.getMessage()));
        } catch (IOException e) {
            e.printStackTrace(listener.error(e.getMessage()));
        }
    }

    String generateServiceId(String slaveRoot) throws IOException {
        return "jenkinsslave-"+slaveRoot.replace(':','_').replace('\\','_').replace('/','_');
    }

    String generateSlaveXml(String id, String java, String vmargs, String args) throws IOException {
        String xml = org.apache.commons.io.IOUtils.toString(getClass().getResourceAsStream("/windows-service/jenkins-slave.xml"), "UTF-8");
        xml = xml.replace("@ID@", id);
        xml = xml.replace("@JAVA@", java);
        xml = xml.replace("@VMARGS@", StringUtils.defaultString(vmargs));
        xml = xml.replace("@ARGS@", args);
        return xml;
    }

    /**
     * Gets the formatted current time stamp.
     *
     * @return the formatted current time stamp.
     */
    protected String getTimestamp() {
        return String.format("[%1$tF %1$tT]", new Date());
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<ComputerLauncher> {
        public String getDisplayName() {
            return Messages.ManagedWindowsServiceLauncher_DisplayName();
        }

        public ListBoxModel doFillCredentialsIdItems(@AncestorInPath ItemGroup context,
                                                     @QueryParameter String host,
                                                     @RelativePath("..") @QueryParameter String name) {
            if (host == null) {
                host = name;
            }
            if (!(context instanceof AccessControlled ? (AccessControlled) context : Jenkins.getInstance()).hasPermission(Computer.CONFIGURE)) {
                return new ListBoxModel();
            }
            return new StandardUsernameListBoxModel().withMatching(CredentialsMatchers.always(),
                    CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class, context,
                            ACL.SYSTEM, WINDOWS_SCHEME, new HostnameRequirement(host)));
        }
    }

    private static final Logger JINTEROP_LOGGER = Logger.getLogger("org.jinterop");

    static {
        JINTEROP_LOGGER.setLevel(Level.WARNING);
    }

    public static StandardUsernamePasswordCredentials lookupSystemCredentials(String credentialsId) {
        return CredentialsMatchers.firstOrNull(
                CredentialsProvider
                        .lookupCredentials(StandardUsernamePasswordCredentials.class, Jenkins.getInstance(), ACL.SYSTEM,
                                WINDOWS_SCHEME),
                CredentialsMatchers.withId(credentialsId)
        );
    }

    static StandardUsernamePasswordCredentials lookupCredentials(StandardUsernamePasswordCredentials credentials, String credentialsId, String userName, Secret password, String host) {
        credentialsId = credentialsId == null
                ? (credentials == null ? null : credentials.getId())
                : credentialsId;
        try {
            // only ever want from the system
            // lookup every time so that we always have the latest
            credentials = lookupSystemCredentials(credentialsId);
            if (credentials != null) {
                return credentials;
            }
        } catch (Throwable t) {
            // ignore
        }
        if (credentials == null) {
            if (credentialsId == null && (userName != null || password != null)) {
                credentials = upgrade(userName, password, host);
            }
        }

        return credentials;
    }

    static synchronized StandardUsernamePasswordCredentials upgrade(String username, Secret password, String description) {
        StandardUsernamePasswordCredentials u = retrieveExistingCredentials(username, password);
        if (u != null) return u;

        // no matching, so make our own.
        u = new UsernamePasswordCredentialsImpl(CredentialsScope.SYSTEM, null, description, username, password == null ? null : password.getEncryptedValue());

        final SecurityContext securityContext = ACL.impersonate(ACL.SYSTEM);
        try {
            CredentialsStore s = CredentialsProvider.lookupStores(Jenkins.getInstance()).iterator().next();
            try {
                s.addCredentials(Domain.global(), u);
                return u;
            } catch (IOException e) {
                // ignore
            }
        } finally {
            SecurityContextHolder.setContext(securityContext);
        }
        return u;
    }

    @VisibleForTesting
    static StandardUsernamePasswordCredentials retrieveExistingCredentials(String username, final Secret password) {
        return CredentialsMatchers.firstOrNull(CredentialsProvider
                .lookupCredentials(StandardUsernamePasswordCredentials.class, Jenkins.getInstance(), ACL.SYSTEM,
                        WINDOWS_SCHEME), allOf(
                withUsername(username),
                new CredentialsMatcher() {
                    public boolean matches(@NonNull Credentials item) {
                        if (item instanceof StandardUsernamePasswordCredentials
                                && password != null
                                && StandardUsernamePasswordCredentials.class.cast(item).getPassword().equals(password)) {
                            return true;
                        }
                        return false;
                    }
                }));
    }
}
