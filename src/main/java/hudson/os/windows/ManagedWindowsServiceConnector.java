package hudson.os.windows;

import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import hudson.Extension;
import hudson.model.TaskListener;
import hudson.slaves.ComputerConnector;
import hudson.slaves.ComputerConnectorDescriptor;
import hudson.util.Secret;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.IOException;

/**
 * {@link ComputerConnector} that delegates to {@link ManagedWindowsServiceLauncher}.
 * @author Kohsuke Kawaguchi
 */
public class ManagedWindowsServiceConnector extends ComputerConnector {
    /**
     * "[DOMAIN\\]USERNAME" to follow the Windows convention.
     */
    @Deprecated
    public final transient String userName;

    @Deprecated
    public final transient Secret password;

    public String credentialsId;

    private transient StandardUsernamePasswordCredentials credentials;

    @Deprecated
    public ManagedWindowsServiceConnector(String userName, String password) {
        this(ManagedWindowsServiceLauncher.upgrade(userName, Secret.fromString(password), null));
    }

    @DataBoundConstructor
    public ManagedWindowsServiceConnector(StandardUsernamePasswordCredentials credentials) {
        this.userName = null;
        this.password = null;
        this.credentials = credentials;
        this.credentialsId = credentials == null ? null : credentials.getId();
    }

    public StandardUsernamePasswordCredentials getCredentials() {
        this.credentials = ManagedWindowsServiceLauncher.lookupCredentials(this.credentials, this.credentialsId, this.userName, this.password, null);
        this.credentialsId = this.credentials == null ? null : this.credentials.getId();
        return credentials;
    }

    @Override
    public ManagedWindowsServiceLauncher launch(final String hostName, TaskListener listener) throws IOException, InterruptedException {
        return new ManagedWindowsServiceLauncher(credentials, hostName, null, null, null);
    }

    @Extension
    public static class DescriptorImpl extends ComputerConnectorDescriptor {
        public String getDisplayName() {
            return Messages.ManagedWindowsServiceLauncher_DisplayName();
        }

        // used by Jelly
        public static final Class<?> CONFIG_DELEGATE_TO = ManagedWindowsServiceLauncher.class;
    }
}
