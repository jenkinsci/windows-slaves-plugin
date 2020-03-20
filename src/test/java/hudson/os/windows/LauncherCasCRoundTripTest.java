package hudson.os.windows;

import hudson.model.Node;
import hudson.slaves.ComputerLauncher;
import hudson.slaves.SlaveComputer;
import io.jenkins.plugins.casc.misc.RoundTripAbstractTest;
import org.jvnet.hudson.test.RestartableJenkinsRule;

import static org.hamcrest.beans.HasPropertyWithValue.hasProperty;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class LauncherCasCRoundTripTest extends RoundTripAbstractTest {
    @Override
    protected void assertConfiguredAsExpected(final RestartableJenkinsRule j, final String s) {
        final Node node = j.j.jenkins.getNode("my-win");
        assertNotNull(node);
        final SlaveComputer computer = (SlaveComputer) node.toComputer();
        assertNotNull(computer);
        final ComputerLauncher launcher = computer.getLauncher();
        assertThat(launcher, instanceOf(ManagedWindowsServiceLauncher.class));
        ManagedWindowsServiceLauncher winLauncher = (ManagedWindowsServiceLauncher) launcher;
        assertEquals("forthewin", winLauncher.host);
        assertEquals("alice", winLauncher.userName);
        //The password is encrypted and a new key is generated every run so it's not decrypted as expected
        //assertEquals("alice", winLauncher.password.getPlainText());
        assertEquals("C:\\Program Files\\Java\\jdk8\\bin\\javaw.exe", winLauncher.javaPath);
        assertEquals("-Xmx200", winLauncher.vmargs);
        final ManagedWindowsServiceAccount account = winLauncher.getAccount();
        assertThat(account, instanceOf(ManagedWindowsServiceAccount.AnotherUser.class));
        ManagedWindowsServiceAccount.AnotherUser aua = (ManagedWindowsServiceAccount.AnotherUser) account;
        assertEquals("bob", aua.userName);
    }

    @Override
    protected String stringInLogExpected() {
        return "Windows";
    }

    @Override
    protected String configResource() {
        return "win-casc.yaml";
    }
}
