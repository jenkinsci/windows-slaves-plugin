/*
 * The MIT License
 *
 * Copyright (c) 2012-, CloudBees, Inc.
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

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardUsernameListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.HostnameRequirement;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.Extension;
import hudson.ExtensionPoint;
import hudson.RelativePath;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Computer;
import hudson.model.Descriptor;
import hudson.model.ItemGroup;
import hudson.os.windows.ManagedWindowsServiceLauncher.AccountInfo;
import hudson.security.ACL;
import hudson.security.AccessControlled;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

/**
 * Encapsulates how to login (a part of {@link ManagedWindowsServiceLauncher}).
 * 
 * @author Kohsuke Kawaguchi
 * @author Vincent Latombe
 * @since 1.448
 */
public abstract class ManagedWindowsServiceAccount extends AbstractDescribableImpl<ManagedWindowsServiceAccount> implements ExtensionPoint {
    public abstract AccountInfo getAccount(ManagedWindowsServiceLauncher launcher);

    /**
     * Logs in with the local system user.
     * This is the default.
     */
    public static final class LocalSystem extends ManagedWindowsServiceAccount {
        @DataBoundConstructor
        public LocalSystem() {}

        @Override
        public AccountInfo getAccount(ManagedWindowsServiceLauncher launcher) {
            return null;
        }

        @Extension(ordinal=100)
        public static class DescriptorImpl extends Descriptor<ManagedWindowsServiceAccount> {
            @Override
            public String getDisplayName() {
                return Messages.ManagedWindowsServiceAccount_LocalSystem_DisplayName();
            }
        }
    }

    /**
     * Logs in with the administrator user account supplied in {@link ManagedWindowsServiceLauncher}.
     */
    public static final class Administrator extends ManagedWindowsServiceAccount {
        @DataBoundConstructor
        public Administrator() {}

        @Override
        public AccountInfo getAccount(ManagedWindowsServiceLauncher launcher) {
            return new AccountInfo(launcher.getCredentials());
        }

        @Extension
        public static class DescriptorImpl extends Descriptor<ManagedWindowsServiceAccount> {
            @Override
            public String getDisplayName() {
                return Messages.ManagedWindowsServiceAccount_Administrator_DisplayName();
            }
        }
    }

    /**
     * Logs in with a separate user.
     */
    public static final class AnotherUser extends ManagedWindowsServiceAccount {
        @Deprecated
        public final transient String userName;
        @Deprecated
        public final transient Secret password;
        private String credentialsId;
        private transient StandardUsernamePasswordCredentials credentials;

        @DataBoundConstructor
        public AnotherUser(String credentialsId) {
            this(ManagedWindowsServiceLauncher.lookupSystemCredentials(credentialsId));
        }

        /**
         * Constructor AnotherUser creates a AnotherUser instance.
         *
         * @param credentials The credentials to connect as.
         */
        public AnotherUser(StandardUsernamePasswordCredentials credentials) {
            this.userName = null;
            this.password = null;
            this.credentials = credentials;
            this.credentialsId = credentials == null ? null : credentials.getId();
        }

        /**
         * Constructor AnotherUser creates a AnotherUser instance.
         *
         * @param userName The username to connect as
         * @param password The password to connect with.
         * @deprecated use the {@link com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials} based version.
         */
        @Deprecated
        public AnotherUser(String userName, Secret password) {
            this.userName = userName;
            this.password = password;
        }

        public String getCredentialsId() {
            if (credentialsId == null && (userName != null || password != null)) {
                initCredentials();
            }
            return credentialsId;
        }

        public StandardUsernamePasswordCredentials getCredentials() {
            initCredentials();
            return this.credentials;
        }

        private void initCredentials() {
            this.credentials = ManagedWindowsServiceLauncher.lookupCredentials(this.credentials, this.credentialsId, userName, password, null);
            this.credentialsId = this.credentials == null ? null : this.credentials.getId();
        }

        @Override
        public AccountInfo getAccount(ManagedWindowsServiceLauncher launcher) {
            return new AccountInfo(getCredentials());
        }

        @Extension
        public static class DescriptorImpl extends Descriptor<ManagedWindowsServiceAccount> {
            @Override
            public String getDisplayName() {
                return Messages.ManagedWindowsServiceAccount_AnotherUser_DisplayName();
            }

            public ListBoxModel doFillCredentialsIdItems(@AncestorInPath ItemGroup context,
                                                         @RelativePath("..") @QueryParameter String host,
                                                         @RelativePath("../..") @QueryParameter String name) {
                ManagedWindowsServiceLauncher.DescriptorImpl launcherDescriptor = (ManagedWindowsServiceLauncher.DescriptorImpl) Jenkins.getInstance().getDescriptorOrDie(ManagedWindowsServiceLauncher.class);
                return launcherDescriptor.doFillCredentialsIdItems(context, host, name);
            }
        }
    }

}
