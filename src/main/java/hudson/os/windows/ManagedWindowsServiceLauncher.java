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

import static hudson.Util.copyStreamAndClose;
import static org.jvnet.hudson.wmi.Win32Service.Win32OwnProcess;

import hudson.AbortException;
import hudson.EnvVars;
import hudson.Extension;
import hudson.Util;
import hudson.model.*;
import hudson.os.windows.ManagedWindowsServiceAccount.AnotherUser;
import hudson.os.windows.ManagedWindowsServiceAccount.LocalSystem;
import hudson.remoting.Channel;
import hudson.remoting.Channel.Listener;
import hudson.remoting.SocketChannelStream;
import hudson.slaves.*;
import hudson.tools.JDKInstaller;
import hudson.tools.JDKInstaller.CPU;
import hudson.tools.JDKInstaller.Platform;
import hudson.util.DescribableList;
import hudson.util.Secret;
import hudson.util.jna.DotNet;

import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jenkins.model.Jenkins;

import org.apache.commons.io.IOUtils;
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
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Windows agent installed/managed as a service entirely remotely.
 *
 * @author Kohsuke Kawaguchi
 */
public class ManagedWindowsServiceLauncher extends ComputerLauncher {

    /**
     * "[DOMAIN\\]USERNAME" to follow the Windows convention.
     */
    public final String userName;

    public final Secret password;

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
        public final String userName;

        public final Secret password;

        @DataBoundConstructor
        public AccountInfo(String userName, String password) {
            this.userName = userName;
            this.password = Secret.fromString(password);
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
     * Host name to connect to. For compatibility reasons, null if the same with the agent name.
     * @since 1.419
     */
    public final String host;

    public ManagedWindowsServiceLauncher(String userName, String password) {
        this(userName, password, null);
    }

    public ManagedWindowsServiceLauncher(String userName, String password, String host) {
        this(userName, password, host, null, null);
    }

    public ManagedWindowsServiceLauncher(String userName, String password, String host, AccountInfo account) {
        this(userName, password, host, account == null ? new LocalSystem() : new AnotherUser(account.userName, account.password), null);
    }

    public ManagedWindowsServiceLauncher(String userName, String password, String host, ManagedWindowsServiceAccount account, String vmargs) {
        this(userName, password, host, account, vmargs, "");
    }

    @DataBoundConstructor
    public ManagedWindowsServiceLauncher(String userName, String password, String host, ManagedWindowsServiceAccount account, String vmargs, String javaPath) {
        this.userName = userName;
        this.password = Secret.fromString(password);
        this.vmargs = Util.fixEmptyAndTrim(vmargs);
        this.javaPath = Util.fixEmptyAndTrim(javaPath);
        this.host = Util.fixEmptyAndTrim(host);
        this.account = account == null ? new LocalSystem() : account;
        this.logOn = null;
    }

    public Object readResolve() {
        if (logOn != null)
            account = new AnotherUser(logOn.userName, logOn.password);
        return this;
    }

    private JIDefaultAuthInfoImpl createAuth() {
        String[] tokens = userName.split("\\\\");
        if (tokens.length == 2)
            return new JIDefaultAuthInfoImpl(tokens[0], tokens[1], Secret.toString(password));
        return new JIDefaultAuthInfoImpl("", userName, Secret.toString(password));
    }

    private NtlmPasswordAuthentication createSmbAuth() {
        JIDefaultAuthInfoImpl auth = createAuth();
        return new NtlmPasswordAuthentication(auth.getDomain(), auth.getUserName(), auth.getPassword());
    }

    public ManagedWindowsServiceAccount getAccount() {
        return account;
    }

    private AccountInfo getLogOn() {
        if (account == null) return null;
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


            Slave node = computer.getNode();
            if (node == null) {
                throw new AbortException("Error retrieving node. Node might have been removed");
            }
            String path = node.getRemoteFS();
            if (path.indexOf(':') == -1) throw new IOException("Remote file system root path of the agent needs to be absolute: " + path);
            SmbFile remoteRoot = new SmbFile("smb://" + name + "/" + path.replace('\\', '/').replace(':', '$') + "/", createSmbAuth());

            if (!remoteRoot.exists())
                remoteRoot.mkdirs();

            String java = resolveJava(computer);

            try {// does Java exist?
                logger.println("Checking if Java exists");
                WindowsRemoteProcessLauncher wrpl = new WindowsRemoteProcessLauncher(name, auth);
                Process proc = wrpl.launch("\"" + java + "\" -version", "c:\\");
                proc.getOutputStream().close();
                StringWriter console = new StringWriter();
                IOUtils.copy(proc.getInputStream(), console);
                proc.getInputStream().close();
                int exitCode = proc.waitFor();
                if (exitCode == 1) {// we'll get this error code if Java is not found
                    logger.println("No Java found. Downloading JDK");
                    JDKInstaller jdki = new JDKInstaller("jdk-6u16-oth-JPR@CDS-CDS_Developer", true);
                    URL jdk = jdki.locate(listener, Platform.WINDOWS, CPU.i386);

                    listener.getLogger().println("Installing JDK");
                    copyStreamAndClose(jdk.openStream(), new SmbFile(remoteRoot, "jdk.exe").getOutputStream());

                    String javaDir = path + "\\jdk"; // this is where we install Java to

                    WindowsRemoteFileSystem fs = new WindowsRemoteFileSystem(name, createSmbAuth());
                    fs.mkdirs(javaDir);

                    jdki.install(new WindowsRemoteLauncher(listener, wrpl), Platform.WINDOWS,
                            fs, listener, javaDir, path + "\\jdk.exe");
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

            String id = findServiceId(services, path);
            if (id == null) {
                id = generateServiceId(path);
                logger.println(Messages.ManagedWindowsServiceLauncher_InstallingAgentService(getTimestamp()));
                if (!DotNet.isInstalled(2, 0, name, auth)) {
                    // abort the launch
                    logger.println(Messages.ManagedWindowsServiceLauncher_DotNetRequired(getTimestamp()));
                    return;
                }

                // copy exe
                logger.println(Messages.ManagedWindowsServiceLauncher_CopyingAgentExe(getTimestamp()));
                //TODO: This executable in the core is designed for the controller, not for the agents
                // Ideally the resources from Windows Agent Installer Module should be used instead (JENKINS-42743)
                copyStreamAndClose(getClass().getResource("/windows-service/jenkins.exe").openStream(), new SmbFile(remoteRoot, "jenkins-agent.exe").getOutputStream());

                copyAgentJar(logger, remoteRoot);

                // copy jenkins-agent.xml
                String xml = createAndCopyJenkinsAgentXml(java, id, logger, remoteRoot);

                // install it as a service
                logger.println(Messages.ManagedWindowsServiceLauncher_RegisteringService(getTimestamp()));
                Document dom = new SAXReader().read(new StringReader(xml));
                Win32Service svc = services.Get("Win32_Service").cast(Win32Service.class);
                int r;
                AccountInfo logOn = getLogOn();
                if (logOn == null) {
                    r = svc.Create(
                            id,
                            dom.selectSingleNode("/service/name").getText() + " at " + path,
                            path + "\\jenkins-agent.exe",
                            Win32OwnProcess, 0, "Manual", true);
                } else {
                    r = svc.Create(
                            id,
                            dom.selectSingleNode("/service/name").getText() + " at " + path,
                            path + "\\jenkins-agent.exe",
                            Win32OwnProcess,
                            0,
                            "Manual",
                            false, // When using a different user, it isn't possible to interact
                            logOn.userName,
                            Secret.toString(logOn.password),
                            null, null, null);

                }
                if (r != 0) {
                    listener.error("Failed to create a service: " + svc.getErrorMessage(r));
                    return;
                }
            } else {
                createAndCopyJenkinsAgentXml(java, id, logger, remoteRoot);
                copyAgentJar(logger, remoteRoot);
            }

            logger.println(Messages.ManagedWindowsServiceLauncher_StartingService(getTimestamp()));
            Win32Service agentService = services.getService(id);
            agentService.start();

            // wait until we see the port.txt, but don't do so forever
            logger.println(Messages.ManagedWindowsServiceLauncher_WaitingForService(getTimestamp()));
            SmbFile portFile = new SmbFile(remoteRoot, "port.txt");
            for (int i = 0; !portFile.exists(); i++) {
                if (i >= 30) {
                    listener.error(Messages.ManagedWindowsServiceLauncher_ServiceDidntRespond(getTimestamp()));
                    return;
                }
                Thread.sleep(1000);
            }
            int p = readSmbFile(portFile);

            // connect
            logger.println(Messages.ManagedWindowsServiceLauncher_ConnectingToPort(getTimestamp(), p));
            final Socket s = new Socket(name, p);

            // ready
            computer.setChannel(
                    new BufferedInputStream(SocketChannelStream.in(s)),
                    new BufferedOutputStream(SocketChannelStream.out(s)),
                    listener.getLogger(),
                    new Listener() {
                        @Override
                        public void onClosed(Channel channel, IOException cause) {
                            afterDisconnect(computer, listener);
                        }
                    });
            //destroy session to free the socket
            JISession.destroySession(session);
        } catch (UnknownHostException e) {
            listener.error(Messages.ManagedWindowsServiceLauncher_UnknownHost(getTimestamp(), e.getMessage()));
        } catch (SmbException | DocumentException e) {
            e.printStackTrace(listener.error(e.getMessage()));
        } catch (JIException e) {
            if (e.getErrorCode() == 5)
                // access denied error
                e.printStackTrace(listener.error(Messages.ManagedWindowsServiceLauncher_AccessDenied(getTimestamp())));
            else
                e.printStackTrace(listener.error(e.getMessage()));
        }
    }

    private String resolveJava(SlaveComputer computer) throws AbortException {
        if (StringUtils.isNotBlank(javaPath)) {
            return getEnvVars(computer).expand(javaPath);
        }
        return "java";
    }

    // -- duplicates code from ssh-slaves-plugin
    private EnvVars getEnvVars(SlaveComputer computer) throws AbortException {
        Slave node = computer.getNode();
        final EnvVars local = node != null ? getEnvVars(node) : null;

        Jenkins jenkins = Jenkins.getInstance();
        if (jenkins != null) {
            final EnvVars global = getEnvVars(jenkins);
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
            }
        } else {
            throw new AbortException("Jenkins is shut down, no agent will be launched.");
        }
        return new EnvVars();
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

    private void checkPort135Access(PrintStream logger, String name, InetAddress host) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, 135), 5000);
        } catch (IOException e) {
            logger.println("Failed to connect to port 135 of " + name + ". Is Windows firewall blocking this port? Or did you disable DCOM service?");
            // again, let it continue.
        }
    }

    /**
     * Determines the host name (or the IP address) to connect to.
     *
     * @param c the computer
     * @return the host name or IP address
     */
    protected String determineHost(Computer c) {
        // If host not provided, default to the agent name
        if (StringUtils.isBlank(host)) {
            return c.getName();
        } else {
            return host;
        }
    }

    private String createAndCopyJenkinsAgentXml(String java, String serviceId, PrintStream logger, SmbFile remoteRoot) throws IOException {
        logger.println(Messages.ManagedWindowsServiceLauncher_CopyingAgentXml(getTimestamp()));
        String xml = generateAgentXml(getClass(), serviceId,
                java + "w.exe", vmargs, "-tcp \"%BASE%\\port.txt\"");
        copyStreamAndClose(new ByteArrayInputStream(xml.getBytes("UTF-8")), new SmbFile(remoteRoot, "jenkins-agent.xml").getOutputStream());
        return xml;
    }

    private void copyAgentJar(PrintStream logger, SmbFile remoteRoot) throws IOException {
        // copy agent.jar
        logger.println(Messages.ManagedWindowsServiceLauncher_CopyingAgentJar(getTimestamp()));
        Jenkins jenkins = Jenkins.getInstance();
        if (jenkins != null) {
            copyStreamAndClose(jenkins.getJnlpJars("agent.jar").getURL().openStream(), new SmbFile(remoteRoot, "agent.jar").getOutputStream());
        } else {
            throw new AbortException("Unable to copy agent JAR. Jenkins has not yet been started.");
        }
    }

    private int readSmbFile(SmbFile f) throws IOException {
        InputStream in = null;
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

            Slave node = computer.getNode();
            if (node != null) {
                String id = findServiceId(services, node.getRemoteFS());
                if (id != null) {
                    Win32Service agentService = services.getService(id);
                    listener.getLogger().println(Messages.ManagedWindowsServiceLauncher_StoppingService(getTimestamp()));
                    agentService.StopService();
                    listener.getLogger().println(Messages.ManagedWindowsServiceLauncher_UnregisteringService(getTimestamp()));
                    agentService.Delete();
                }
            } else {
                throw new AbortException("Node might have been already removed, skipping afterDisconnect logic.");
            }
            //destroy session to free the socket
            JISession.destroySession(session);
        } catch (JIException | IOException e) {
            e.printStackTrace(listener.error(e.getMessage()));
        }
    }

    private
    String getServiceIdSuffix(String agentRoot) throws IOException {
        return agentRoot.replace(':', '_').replace('\\', '_').replace('/', '_');
    }

    String generateServiceId(String agentRoot) throws IOException {
        return "jenkinsagent-" + getServiceIdSuffix(agentRoot);
    }

    private
    String tryServiceId(SWbemServices services, String serviceId) {
        try {
            Win32Service agentService = services.getService(serviceId);
            if (agentService != null)
                return serviceId;
        } catch (Exception ex) {
        }
        return null;
    }

    String findServiceId(SWbemServices services, String agentRoot) throws IOException {
        String id = getServiceIdSuffix(agentRoot);
        String serviceId = tryServiceId(services, generateServiceId(id));
        if (serviceId != null)
            return serviceId;
        return tryServiceId(services, "jenkinsslave-" + id);
    }

    static String generateAgentXml(Class<?> clazz, String id, String java, String vmargs, String args) throws IOException {
        String xml = IOUtils.toString(clazz.getResourceAsStream("configsamples/jenkins-agent.xml"), "UTF-8");
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
    }

    private static final Logger JINTEROP_LOGGER = Logger.getLogger("org.jinterop");

    static {
        JINTEROP_LOGGER.setLevel(Level.WARNING);
    }
}
