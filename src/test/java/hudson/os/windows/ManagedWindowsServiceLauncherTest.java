/*
 * The MIT License
 *
 * Copyright 2015 Jesse Glick.
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

import hudson.slaves.DumbSlave;
import hudson.util.Secret;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.jvnet.hudson.test.JenkinsRule;

public class ManagedWindowsServiceLauncherTest {

    @Rule public JenkinsRule r = new JenkinsRule();

    @Test public void configRoundTrip() throws Exception {
        assertTrue(r.jenkins.getPluginManager().getPlugin("windows-slaves").isActive()); // verifying JENKINS-28816
        DumbSlave s = r.createSlave();
        ManagedWindowsServiceLauncher launcher = new ManagedWindowsServiceLauncher("jenkins", "jEnKiNs", "nowhere.net", new ManagedWindowsServiceAccount.AnotherUser("bob", Secret.fromString("s3cr3t")), "-Xmx128m", "C:\\stuff\\java");
        s.setLauncher(launcher);
        r.assertEqualDataBoundBeans(launcher, r.configRoundtrip(s).getLauncher());
    }

}